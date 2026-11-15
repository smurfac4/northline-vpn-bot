from support import install_test_catalogs
import base64
from contextlib import contextmanager
from dataclasses import replace
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import URLError
from unittest.mock import Mock, patch

import settings
from backend.admin import Admin
from backend.main import API
from backend.service import VPN, Problem
from deploy import node_control
import run


class ServiceAuditTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        config=patch.multiple(settings,ROOT=self.root,MODE='live',DB=self.root/'data/fixture.sqlite3',
            ADMIN_IDS='10',RESTART_FILE=self.root/'restart.request',NODES=self.root/'nodes.json',PROXY_NODES=self.root/'proxy.json')
        config.start();self.addCleanup(config.stop)
        lookup=patch('backend.registry.detect_location',return_value=None);lookup.start();self.addCleanup(lookup.stop)
        self.vpn=VPN();self.admin=Admin(self.vpn)

    def test_issue_uses_catalog_after_waiting_for_registry_lock(self):
        waiting=threading.Event();actual_lock=threading.RLock()
        class ObservedLock:
            def __enter__(self):
                if threading.current_thread().name=='issue-worker':waiting.set()
                actual_lock.acquire();return self
            def __exit__(self,*args):actual_lock.release()
        self.vpn.lock=ObservedLock();errors=[]
        def issue():
            try:self.vpn.issue(20,'wg-eu')
            except Exception as error:errors.append(error)
        with self.vpn.lock:
            worker=threading.Thread(target=issue,name='issue-worker');worker.start()
            self.assertTrue(waiting.wait(2))
            self.vpn.nodes['wg-eu']=replace(self.vpn.nodes['wg-eu'],subnet=ipaddress.IPv4Network('10.200.0.0/24'))
        worker.join(3);self.assertFalse(worker.is_alive());self.assertFalse(errors)
        self.assertEqual(self.vpn.current(20)['address'],'10.200.0.2')

    def test_metrics_from_changed_server_are_discarded(self):
        def remote(*args):
            node=self.vpn.nodes['wg-eu']
            self.vpn.nodes['wg-eu']=replace(node,endpoint='changed.example:51820')
            return json.dumps({'rx_bytes':100,'tx_bytes':200,'peer_count':1})
        with patch('backend.admin.wg.control',side_effect=remote):self.admin._probe('device','wg-eu')
        with self.vpn.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM server_metrics').fetchone()[0],0)

    def test_out_of_range_metrics_do_not_crash_worker_or_publish_fake_speed(self):
        with patch('backend.admin.wg.control',return_value=json.dumps({'rx_bytes':2**100,'tx_bytes':1,'peer_count':1})):
            self.admin._probe('device','wg-eu')
        with self.vpn.db() as db:self.assertEqual(db.execute('SELECT state FROM server_metrics').fetchone()[0],'unavailable')

    def test_failed_audit_does_not_undo_successful_admin_operation(self):
        @contextmanager
        def failed_db():
            raise sqlite3.OperationalError('database locked')
            yield
        with patch.object(self.vpn,'db',failed_db),patch('builtins.print'):
            self.assertFalse(self.admin.audit(10,'saved','target'))

    def test_admin_snapshot_batches_profile_reads(self):
        self.admin.observe(20,{'id':20,'first_name':'User'},'bot','device','status','',200,1)
        self.vpn.issue(20,'wg-eu');self.vpn.issue(20,'tg-eu',scope='telegram')
        with patch.object(self.vpn,'statuses',side_effect=AssertionError('per-user DB loop')):
            snapshot=self.admin.snapshot(10)
        user=next(row for row in snapshot['users'] if row['user_id']==20)
        self.assertEqual(user['profiles']['device']['node'],'wg-eu')
        self.assertEqual(user['profiles']['telegram']['node'],'tg-eu')

    def test_metrics_reset_failure_cannot_commit_server_file(self):
        node={'id':'eu-1','name':'Original','subnet':'10.77.0.0/24','endpoint':'vpn.example.com:51820',
              'public_key':base64.b64encode(b'x'*32).decode(),'ssh_host':'northline-eu-1','enabled':True}
        version=self.admin.real_servers(10)['catalogs']['device']['revision']
        self.admin.edit_real_server(10,{'scope':'device','action':'save','expected_revision':version,'server':node})
        original=settings.NODES.read_bytes();version=self.admin.real_servers(10)['catalogs']['device']['revision']
        @contextmanager
        def failed_db():
            raise sqlite3.OperationalError('database locked')
            yield
        with patch.object(self.vpn,'db',failed_db),self.assertRaises(sqlite3.Error):
            self.admin.edit_real_server(10,{'scope':'device','action':'save','original_id':'eu-1','expected_revision':version,'server':{**node,'name':'Not saved'}})
        self.assertEqual(settings.NODES.read_bytes(),original)

    def test_http_database_failure_returns_json_without_private_details(self):
        handler=object.__new__(API);handler.route=Mock(side_effect=sqlite3.OperationalError('secret DB path'))
        handler.reply=Mock();handler.handle_request()
        self.assertEqual(handler.reply.call_args.args[0],503)
        self.assertNotIn('secret',json.dumps(handler.reply.call_args.args[1]))

    def test_http_body_timeout_and_truncation_are_explicit_errors(self):
        handler=object.__new__(API);handler.headers={'Content-Length':'8'};handler.rfile=Mock()
        handler.rfile.read.side_effect=TimeoutError
        with self.assertRaises(Problem) as error:handler.body()
        self.assertEqual(error.exception.status,408)
        handler.rfile=io.BytesIO(b'{}')
        with self.assertRaises(Problem) as error:handler.body()
        self.assertEqual(error.exception.status,400)

    def test_marker_write_failure_unlocks_current_service(self):
        self.vpn.restarting=True
        with patch('backend.admin.os.replace',side_effect=PermissionError),patch('builtins.print'):
            self.assertFalse(self.admin.request_restart())
        self.assertFalse(self.vpn.restarting)
        self.assertEqual(self.vpn.issue(20,'wg-eu')['status'],'active')

    def test_stale_measurement_does_not_report_current_speed(self):
        with self.vpn.db() as db:
            db.execute("INSERT INTO server_metrics VALUES ('device','wg-eu',?,'online',10,100,200,90,80,1,'',NULL)",(int(time.time())-600,))
        with patch.object(settings,'MODE','live'):
            server=next(row for row in self.admin.servers() if row['scope']=='device' and row['id']=='wg-eu')
        self.assertEqual(server['metric']['state'],'stale')
        self.assertIsNone(server['metric']['download_mbps'])


    def test_excessively_nested_json_is_rejected_as_bad_request(self):
        raw=('['*1500+']'*1500).encode()
        handler=object.__new__(API);handler.headers={'Content-Length':str(len(raw))};handler.rfile=io.BytesIO(raw)
        with self.assertRaises(Problem) as error:handler.body()
        self.assertEqual(error.exception.status,400)




class NodeRevocationTests(unittest.TestCase):
    def test_permanent_peer_survives_sync_but_old_zero_expiry_revocation_does_not(self):
        permanent=base64.b64encode(b'p'*32).decode(); revoked=base64.b64encode(b'r'*32).decode()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'subnet').write_text('10.77.0.0/24')
            state=root/'peers.json'
            state.write_text(json.dumps({permanent:{'address':'10.77.0.2/32','expires':0,'unlimited':True},
                                         revoked:{'address':'10.77.0.3/32','expires':0}}))
            with patch.object(node_control,'DIRECTORY',root),patch.object(node_control,'wg',return_value='') as wg:
                node_control.control(['sync'])
            self.assertIn(permanent,json.loads(state.read_text())); self.assertNotIn(revoked,json.loads(state.read_text()))
            self.assertTrue(any(call.args==('set','wg0','peer',permanent,'allowed-ips','10.77.0.2/32') for call in wg.call_args_list))

    def test_permanent_peer_can_be_issued_and_revoked(self):
        key=base64.b64encode(b'p'*32).decode()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'subnet').write_text('10.77.0.0/24')
            with patch.object(node_control,'DIRECTORY',root),patch.object(node_control,'wg',return_value=''):
                node_control.control(['add',key,'10.77.0.2/32','0'])
                self.assertTrue(json.loads((root/'peers.json').read_text())[key]['unlimited'])
                node_control.control(['remove',key]); node_control.control(['sync'])
                self.assertEqual(json.loads((root/'peers.json').read_text()),{})

    def test_failed_final_save_cannot_restore_revoked_peer(self):
        key=base64.b64encode(b'x'*32).decode()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'subnet').write_text('10.77.0.0/24')
            state=root/'peers.json';state.write_text(json.dumps({key:{'address':'10.77.0.2/32','expires':int(time.time())+3600}}))
            real_save=node_control.save;writes=[]
            def fail_final(path,peers):
                writes.append(1)
                if len(writes)==2:raise PermissionError('disk failure')
                return real_save(path,peers)
            def wg(*args):return key+'\n' if args==('show','wg0','peers') else ''
            with patch.object(node_control,'DIRECTORY',root),patch.object(node_control,'wg',side_effect=wg) as commands:
                with patch.object(node_control,'save',side_effect=fail_final),self.assertRaises(PermissionError):node_control.control(['remove',key])
                self.assertEqual(json.loads(state.read_text())[key]['expires'],0)
                node_control.control(['sync'])
                self.assertFalse(any('allowed-ips' in call.args for call in commands.call_args_list))
                self.assertEqual(json.loads(state.read_text()),{})

    def test_unknown_state_entry_still_removes_peer_from_interface(self):
        key=base64.b64encode(b'y'*32).decode()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'subnet').write_text('10.77.0.0/24')
            with patch.object(node_control,'DIRECTORY',root),patch.object(node_control,'wg') as wg:
                node_control.control(['remove',key])
            wg.assert_called_once_with('set','wg0','peer',key,'remove')


class StartupAuditTests(unittest.TestCase):
    def load_helper(self,name):
        spec=importlib.util.spec_from_file_location(name.replace('-','_'),Path(__file__).resolve().parents[1]/'deploy'/f'{name}.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_supervisor_keeps_children_in_its_process_group(self):
        marker=Mock();marker.exists.return_value=False
        child=Mock();child.poll.return_value=0;child.returncode=0
        with patch.dict(os.environ,{'NORTHLINE_MANAGED':'1'}),patch.object(run.settings,'RESTART_FILE',marker),patch('run.signal.signal'),patch('run.subprocess.Popen',return_value=child) as launch:
            run.main()
        self.assertFalse(launch.call_args.kwargs['start_new_session'])

    def test_transient_public_failure_preserves_the_running_tunnel(self):
        module=self.load_helper('start-local');app=Mock();app.poll.return_value=None
        with patch.object(module.time,'monotonic',side_effect=[0,31,31,62,62,93,93]),patch.object(module.time,'sleep',side_effect=[None,None,KeyboardInterrupt]),patch.object(module,'healthy_url',return_value=False) as health,patch('builtins.print'):
            with self.assertRaises(KeyboardInterrupt):module.monitor(app,None,'https://test.example')
        self.assertEqual(health.call_count,3)
        app.terminate.assert_not_called()

    def test_monitor_recovers_application_without_restarting_tunnel(self):
        module=self.load_helper('start-local');app=Mock();app.poll.return_value=1
        replacement=Mock();replacement.poll.return_value=None
        tunnel=Mock();tunnel.poll.return_value=None
        recover=Mock(return_value=replacement)
        with patch.object(module.time,'sleep',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):module.monitor(app,tunnel,'https://test.example',recover)
        recover.assert_called_once();tunnel.terminate.assert_not_called()

    def test_lost_tunnel_registration_triggers_recovery(self):
        module=self.load_helper('start-local');app=Mock();app.poll.return_value=None
        tunnel=Mock();tunnel.poll.return_value=None
        with patch.object(module.time,'monotonic',side_effect=[0,31,31,62,62,93]),patch.object(module.time,'sleep'),patch.object(module,'healthy_url',return_value=False),patch.object(module,'tunnel_registration_lost',return_value=True):
            with self.assertRaisesRegex(RuntimeError,'registration was lost'):
                module.monitor(app,tunnel,'https://test.example')

    def test_tunnel_registration_check_ignores_errors_before_reconnection(self):
        module=self.load_helper('start-local')
        with tempfile.TemporaryDirectory() as folder,patch.object(module,'DATA',Path(folder)):
            log=Path(folder)/'cloudflared.log'
            self.assertFalse(module.tunnel_registration_lost())
            log.write_text('Unauthorized: Tunnel not found\n')
            self.assertTrue(module.tunnel_registration_lost())
            with log.open('a') as stream:stream.write('Registered tunnel connection\n')
            self.assertFalse(module.tunnel_registration_lost())

    def test_run_lock_blocks_duplicate_and_survives_inherited_descriptor(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(run.settings,'ROOT',Path(folder)),patch.dict(run.START_ENV,{},clear=True),patch.dict(os.environ,{},clear=True):
            fd=run.acquire_instance_lock()
            try:
                with self.assertRaises(BlockingIOError):run.acquire_instance_lock()
                with patch.dict(os.environ,{'NORTHLINE_RUN_LOCK_FD':str(fd)}):
                    self.assertEqual(run.acquire_instance_lock(),fd)
                self.assertTrue(os.get_inheritable(fd))
            finally:os.close(fd)

    def test_stuck_child_is_killed_after_a_bounded_grace_period(self):
        marker=Mock();marker.exists.return_value=False
        child=Mock();child.poll.side_effect=[None,0,None];child.returncode=1
        child.wait.side_effect=[run.subprocess.TimeoutExpired('child',3),None]
        with patch.object(run.settings,'RESTART_FILE',marker),patch.object(run.settings,'TOKEN',''),patch('run.signal.signal'),patch('run.subprocess.Popen',return_value=child),patch('run.time.sleep'):
            self.assertEqual(run.main(),1)
        child.kill.assert_called_once()

    def test_monitor_detects_tunnel_process_exit(self):
        module=self.load_helper('start-local');app=Mock();app.poll.return_value=None
        tunnel=Mock();tunnel.poll.return_value=1
        with self.assertRaisesRegex(RuntimeError,'managed process'):module.monitor(app,tunnel,'https://test.example')



    def test_unexpected_clean_child_exit_is_a_service_failure(self):
        marker=Mock();marker.exists.return_value=False
        child=Mock();child.poll.return_value=0;child.returncode=0
        with patch.object(run.settings,'RESTART_FILE',marker),patch('run.signal.signal'),patch('run.subprocess.Popen',return_value=child):
            self.assertEqual(run.main(),1)

    def test_failed_tunnel_startup_restores_previous_env(self):
        spec=importlib.util.spec_from_file_location('start_local_audit',Path(__file__).resolve().parents[1]/'deploy/start-local.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);data=root/'data';data.mkdir()
            env=root/'.env';original=b'BOT_TOKEN=placeholder\nVPN_MODE=live\nPERSONAL_TEST=1\nALLOWED_TELEGRAM_IDS=10\nADMIN_TELEGRAM_IDS=10\nPUBLIC_URL=https://previous.example\n';env.write_bytes(original)
            tunnel=Mock();tunnel.poll.return_value=None;tunnel.pid=101
            app=Mock();app.poll.return_value=1;app.pid=102
            def launch(*args,**kwargs):
                if 'tunnel' in args[0]:
                    kwargs['stdout'].write('https://new-test.trycloudflare.com\n');kwargs['stdout'].flush();return tunnel
                return app
            connection=Mock();connection.__enter__=Mock(return_value=connection);connection.__exit__=Mock(return_value=False);connection.connect_ex.return_value=1
            old_mask=os.umask(0o077)
            try:
                with patch.object(module,'ROOT',root),patch.object(module,'DATA',data),patch.object(sys,'argv',['start-local.py','--tunnel']),patch.dict(os.environ,{},clear=True),patch.object(module.socket,'socket',return_value=connection),patch.object(module.shutil,'which',return_value='/installed/cloudflared'),patch.object(module.subprocess,'Popen',side_effect=launch):
                    with self.assertRaises(RuntimeError):module.main()
            finally:os.umask(old_mask)
            self.assertEqual(env.read_bytes(),original)
            tunnel.terminate.assert_called_once();tunnel.wait.assert_called_once()
