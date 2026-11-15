from support import install_test_catalogs
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from urllib.parse import urlsplit,parse_qs

import settings
from backend import proxy
from backend.admin import Admin
from backend.main import API
from backend.service import VPN,Problem
from backend.wireguard import WireGuardError
from bot import main as bot


class ManagedProxyTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.state=self.root/'proxy'
        config=patch.multiple(settings,MODE='live',ROOT=self.root,DB=self.root/'vpn.sqlite3',
            ENV_FILE=self.root/'.env',DEVICE_NODES=self.root/'device-vpn.json',ADMIN_IDS='10',ALLOW='*',MTPROXY_NODE_ID='tg-test',MTPROXY_STATE_DIR=self.state)
        config.start();self.addCleanup(config.stop)
        self.vpn=VPN();self.device=self.vpn.issue(10,'wg-eu')
        self.node=proxy.ProxyNode('tg-test','Telegram test','proxy.example.com',8443)
        self.vpn.catalogs['telegram']={'tg-test':self.node}
        live=patch.object(settings,'MODE','live');live.start();self.addCleanup(live.stop)
        self.device=self.vpn.status(10)
        def ack():
            path=self.state/'desired.json'
            return {'version':1,'running':True,'updated':int(time.time()),'host':'proxy.example.com','port':8443,'revision':json.loads(path.read_text())['revision'] if path.exists() else 'empty'}
        status=patch('backend.proxy.service_status',side_effect=ack);status.start();self.addCleanup(status.stop)

    def issue(self,user=10):return self.vpn.issue(user,'tg-test',scope='telegram')

    def test_proxy_speed_uses_counter_deltas_and_resets_after_transport_restart(self):
        admin=Admin(self.vpn)
        def sample(at,rx,tx,generation='a'*16):
            value={'sampled_at':at,'rx_bytes':rx,'tx_bytes':tx,'peer_count':3,'sample_id':generation}
            with patch('backend.proxy.metrics',return_value=value),patch('backend.admin.wg.control') as ssh:
                admin._probe('telegram',self.node.id,self.node);ssh.assert_not_called()
            with self.vpn.db() as db:return dict(db.execute("SELECT * FROM server_metrics WHERE scope='telegram'").fetchone())
        first=sample(100,1000,2000);self.assertIsNone(first['download_mbps'])
        second=sample(110,5001000,10002000)
        self.assertEqual(second['download_mbps'],8);self.assertEqual(second['upload_mbps'],4)
        self.assertEqual(second['peer_count'],3);self.assertIsNone(second['latency_ms'])
        restarted=sample(120,50001000,100002000,'b'*16)
        self.assertIsNone(restarted['download_mbps']);self.assertIsNone(restarted['upload_mbps'])
        decreased=sample(130,1,1,'b'*16);self.assertIsNone(decreased['download_mbps'])

    def test_unavailable_proxy_metrics_do_not_report_fake_speed_or_ssh_error(self):
        admin=Admin(self.vpn)
        with patch('backend.proxy.metrics',side_effect=WireGuardError('offline')):admin._probe('telegram',self.node.id,self.node)
        with self.vpn.db() as db:row=db.execute("SELECT * FROM server_metrics WHERE scope='telegram'").fetchone()
        self.assertEqual(row['state'],'unavailable');self.assertIsNone(row['download_mbps'])
        self.assertNotIn('SSH',row['note'])

    def test_measure_starts_managed_proxy_collection_without_duplicate_threads(self):
        admin=Admin(self.vpn)
        with patch('backend.admin.threading.Thread') as thread:
            self.assertTrue(admin.measure(10,{'scope':'telegram','node':self.node.id})['pending'])
            admin.measure(10,{'scope':'telegram','node':self.node.id})
            thread.assert_called_once();thread.return_value.start.assert_called_once()
        self.assertTrue(next(row for row in admin.servers() if row['scope']=='telegram')['measurable'])

    def test_proxy_single_click_measurement_samples_both_ends_of_the_window(self):
        admin=Admin(self.vpn);key=('telegram',self.node.id);admin.pending.add(key)
        values=[{'sampled_at':100,'rx_bytes':0,'tx_bytes':0,'peer_count':0,'sample_id':'a'*16},
                {'sampled_at':110,'rx_bytes':0,'tx_bytes':0,'peer_count':0,'sample_id':'a'*16}]
        with patch('backend.proxy.metrics',side_effect=values),patch('backend.admin.time.sleep') as pause:
            admin._measure_window(*key,self.node)
        pause.assert_called_once_with(10);self.assertNotIn(key,admin.pending)
        with self.vpn.db() as db:row=db.execute("SELECT * FROM server_metrics WHERE scope='telegram'").fetchone()
        self.assertEqual(row['download_mbps'],0);self.assertEqual(row['upload_mbps'],0)

    def test_admin_can_invite_non_admin_for_telegram_only(self):
        admin=Admin(self.vpn);admin.observe(20,{},'miniapp','telegram','issue','',403,1)
        with patch.object(settings,'ALLOW','10'):
            with self.assertRaises(Problem) as error:self.issue(20)
            self.assertEqual(error.exception.status,403)
            admin.account_policy(10,{'user_id':20,'scope':'telegram','live_access':True})
            self.assertEqual(self.issue(20)['status'],'active')
            self.assertEqual(self.vpn.visible_nodes('device',20),[])
            self.assertEqual([node['id'] for node in self.vpn.visible_nodes('telegram',20)],['tg-test'])
            with self.assertRaises(Problem) as error:self.vpn.issue(20,'wg-eu',scope='device')
            self.assertEqual(error.exception.status,403)
            user=next(row for row in admin.snapshot(10)['users'] if row['user_id']==20)
            self.assertFalse(user['is_admin']);self.assertTrue(user['live_access']['telegram']['allowed'])
            self.assertFalse(user['live_access']['device']['allowed'])
            self.assertEqual(user['live_access']['telegram']['source'],'account')

    def test_closing_mode_revokes_its_secret_without_touching_other_users(self):
        admin=Admin(self.vpn);admin.observe(20,{},'miniapp','telegram','issue','',200,1)
        owner=self.issue();profile=self.issue(20)
        admin.account_policy(10,{'user_id':20,'scope':'telegram','live_access':False})
        self.assertEqual(self.vpn.status(20,'telegram')['status'],'revoked')
        self.assertEqual(self.vpn.status(10,'telegram'),owner);self.assertEqual(self.vpn.status(10),self.device)
        self.assertEqual(len(json.loads((self.state/'desired.json').read_text())['profiles']),1)
        with self.assertRaises(Problem) as error:self.issue(20)
        self.assertEqual(error.exception.status,403)

    def test_permission_denial_survives_transport_failure_and_retries_revocation(self):
        admin=Admin(self.vpn);admin.observe(20,{},'miniapp','telegram','issue','',200,1);self.issue(20)
        with patch('backend.proxy.sync',side_effect=WireGuardError('offline')):
            result=admin.account_policy(10,{'user_id':20,'scope':'telegram','live_access':False})
        self.assertTrue(result['pending_revoke']);self.assertFalse(self.vpn.live_access(20)['telegram']['allowed'])
        self.assertEqual(self.vpn.status(20,'telegram')['status'],'revoking')
        self.vpn.reconcile_once();self.assertEqual(self.vpn.status(20,'telegram')['status'],'revoked')

    def test_status_returns_only_authorized_mode_servers(self):
        admin=Admin(self.vpn);admin.observe(20,{},'miniapp','telegram','status','',200,1)
        with patch.object(settings,'ALLOW','10'):
            admin.account_policy(10,{'user_id':20,'scope':'telegram','live_access':True})
            for scope,expected in [('device',[]),('telegram',['tg-test'])]:
                handler=object.__new__(API);handler.server=SimpleNamespace(vpn=self.vpn,admin=admin)
                handler.path='/api/status?scope='+scope;handler.command='GET'
                handler.actor=Mock(return_value=20);handler.reply=Mock()
                handler.route();code,body=handler.reply.call_args.args
                self.assertEqual(code,200);self.assertEqual([node['id'] for node in body['nodes']],expected)
                self.assertFalse(body['live_access']['device']['allowed'])
                self.assertTrue(body['live_access']['telegram']['allowed'])

    def test_live_connection_is_native_link_without_wireguard_download(self):
        profile=self.issue();connection=self.vpn.connection(10,'telegram','ios',profile['id'],'active')
        self.assertIsNone(connection['download'])
        url=urlsplit(connection['connect_url']);query=parse_qs(url.query)
        self.assertEqual((url.scheme,url.hostname,url.path),('https','t.me','/proxy'))
        self.assertEqual(query['server'],['proxy.example.com']);self.assertEqual(query['port'],['8443'])
        self.assertRegex(query['secret'][0],r'^dd[0-9a-f]{32}$')
        self.assertNotIn(query['secret'][0][2:],json.dumps(self.vpn.statuses(10)))
        self.assertEqual((self.state/'desired.json').stat().st_mode&0o777,0o600)

    def test_revocation_removes_key_and_preserves_device_profile(self):
        profile=self.issue();old=json.loads((self.state/'desired.json').read_text())['profiles'][0]['secret']
        self.vpn.revoke(10,profile['id'],'active','telegram')
        self.assertEqual(json.loads((self.state/'desired.json').read_text())['profiles'],[])
        self.assertEqual(self.vpn.current(10,'telegram')['private_key'],'')
        self.assertEqual(self.vpn.status(10),self.device)
        self.issue();new=json.loads((self.state/'desired.json').read_text())['profiles'][0]['secret'];self.assertNotEqual(old,new)

    def test_session_pause_and_resume_preserve_profile_secret_expiry_and_other_access(self):
        profile=self.issue();other=self.issue(20)
        original=dict(self.vpn.current(10,'telegram'))
        paused=self.vpn.session(10,False,profile['id'],True)
        self.assertFalse(paused['session']['enabled']);self.assertFalse(paused['session']['pending'])
        self.assertEqual(paused['status'],'active')
        desired=json.loads((self.state/'desired.json').read_text())['profiles']
        self.assertEqual([item['secret'] for item in desired],[self.vpn.current(20,'telegram')['private_key']])
        with self.assertRaises(Problem):self.vpn.connection(10,'telegram')
        resumed=self.vpn.session(10,True,profile['id'],False)
        self.assertEqual(resumed,profile)
        self.assertEqual(dict(self.vpn.current(10,'telegram')),original)
        self.assertEqual(self.vpn.status(20,'telegram'),other)
        self.assertEqual(self.vpn.status(10),self.device)
        self.assertIn(original['private_key'],[item['secret'] for item in json.loads((self.state/'desired.json').read_text())['profiles']])

    def test_managed_profile_has_permanent_secret_after_time_passes(self):
        profile=self.issue(); secret=self.vpn.current(10,'telegram')['private_key']
        self.assertEqual(profile['expires'],0)
        with patch('backend.service.time.time',return_value=time.time()+100*365*86400):
            self.vpn.reconcile_once(); proxy.sync(self.vpn)
            self.assertEqual(self.vpn.status(10,'telegram'),profile)
        self.assertIn({'secret':secret,'expires':0},json.loads((self.state/'desired.json').read_text())['profiles'])

    def test_lost_session_ack_is_pending_and_reconciles_without_new_profile(self):
        profile=self.issue()
        with patch('backend.proxy.sync',side_effect=WireGuardError('offline')):
            with self.assertRaises(WireGuardError):self.vpn.session(10,False,profile['id'],True)
        self.assertTrue(self.vpn.status(10,'telegram')['session']['pending'])
        self.vpn.reconcile_once()
        paused=self.vpn.status(10,'telegram')
        self.assertEqual(paused['id'],profile['id']);self.assertFalse(paused['session']['pending'])
        self.assertFalse(paused['session']['enabled'])
        self.assertEqual(json.loads((self.state/'desired.json').read_text())['profiles'],[])

    def test_stale_session_command_cannot_toggle_new_profile_or_overwrite_newer_state(self):
        profile=self.issue();self.vpn.session(10,False,profile['id'],True)
        with self.assertRaises(Problem) as error:self.vpn.session(10,True,profile['id'],True)
        self.assertEqual(error.exception.status,409)
        for value in (None,'false',0):
            with self.subTest(value=value),self.assertRaises(Problem):self.vpn.session(10,value,profile['id'],False)
        self.vpn.revoke(10,profile['id'],'active','telegram');new=self.issue()
        with self.assertRaises(Problem):self.vpn.session(10,False,profile['id'],True)
        self.assertEqual(self.vpn.status(10,'telegram'),new)

    def test_session_cannot_resume_after_expiry_or_permission_denial(self):
        profile=self.issue();self.vpn.session(10,False,profile['id'],True)
        with patch.object(settings,'ALLOW','20'),self.assertRaises(Problem):self.vpn.session(10,True,profile['id'],False)
        with self.vpn.db() as db:db.execute('UPDATE profiles SET expires=1 WHERE id=?',(profile['id'],))
        with self.assertRaises(Problem):self.vpn.session(10,True,profile['id'],False)

    def test_session_api_is_bound_to_profile_and_scope(self):
        profile=self.issue()
        handler=object.__new__(API);handler.server=SimpleNamespace(vpn=self.vpn)
        handler.path='/api/session?scope=telegram';handler.command='POST';handler.actor=Mock(return_value=10)
        body={'scope':'telegram','expected_profile':profile['id'],'expected_enabled':True,'enabled':False}
        handler.body=Mock(return_value=body);handler.reply=Mock();handler.route()
        self.assertFalse(handler.reply.call_args.args[1]['session']['enabled'])
        handler.body=Mock(return_value={**body,'scope':'device'})
        with self.assertRaises(Problem) as error:handler.route()
        self.assertEqual(error.exception.status,400)
        self.assertEqual(self.vpn.status(10),self.device)

    def test_expiration_removes_secret(self):
        self.issue()
        with self.vpn.db() as db:db.execute("UPDATE profiles SET expires=? WHERE scope='telegram'",(int(time.time())-1,))
        self.vpn.reconcile_once()
        self.assertEqual(self.vpn.status(10,'telegram')['status'],'expired')
        self.assertEqual(json.loads((self.state/'desired.json').read_text())['profiles'],[])

    def test_failed_ack_leaves_retryable_creating_profile(self):
        with patch('backend.proxy.sync',side_effect=WireGuardError('offline')):
            with self.assertRaises(WireGuardError):self.issue()
        self.assertEqual(self.vpn.status(10,'telegram')['status'],'creating')
        self.vpn.reconcile_once();self.assertEqual(self.vpn.status(10,'telegram')['status'],'active')

    def test_unmanaged_proxy_is_never_issued(self):
        self.vpn.catalogs['telegram']['other']=proxy.ProxyNode('other','Other','other.example.com',8443)
        with self.assertRaises(Problem) as error:self.vpn.issue(10,'other',scope='telegram')
        self.assertEqual(error.exception.status,503)

    def test_catalog_address_must_match_running_transport(self):
        for host,port in [('wrong.example.com',8443),('proxy.example.com',443)]:
            with self.subTest(host=host,port=port):
                self.vpn.catalogs['telegram']['tg-test']=proxy.ProxyNode('tg-test','Test',host,port)
                self.assertFalse(self.vpn.available('telegram'))
                with self.assertRaises(Problem) as error:self.issue()
                self.assertEqual(error.exception.status,503)

    def test_full_proxy_keeps_existing_access(self):
        profiles=[self.issue(user) for user in range(1,17)]
        with self.assertRaises(Problem) as error:self.issue(17)
        self.assertEqual(error.exception.status,409)
        self.assertEqual(self.vpn.status(1,'telegram'),profiles[0])

    def test_telegram_only_readiness_does_not_require_wireguard(self):
        admin=object.__new__(Admin)
        with patch.multiple(settings,TOKEN='token',BOT_KEY='internal',PUBLIC_URL='https://app.example.com'),patch('backend.admin.wg.load_nodes',return_value={}),patch('backend.admin.proxy.load_nodes',return_value={'tg-test':self.node}),patch('backend.admin.shutil.which',return_value=None),patch.dict(os.environ,{},clear=True):
            readiness=admin.readiness()
        self.assertTrue(readiness['live_ready']);self.assertTrue(readiness['telegram_ready']);self.assertFalse(readiness['device_ready'])

    def test_bot_offers_native_link_without_file_export(self):
        profile=self.issue();connection=self.vpn.connection(10,'telegram','ios')
        with patch.object(bot,'api',return_value=connection),patch.object(bot,'send') as send:
            bot.connection_message(10,10,'telegram')
        rows=send.call_args.args[2]
        self.assertEqual(rows[0][0]['url'],connection['connect_url'])
        self.assertFalse(any('export' in item.get('callback_data','') for row in rows for item in row))


class ProxyHealthTests(unittest.TestCase):
    def test_invalid_or_stale_status_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(settings,'MTPROXY_STATE_DIR',Path(folder)):
            path=Path(folder)/'status.json'
            for value in [[],{}, {'version':1,'running':False,'updated':int(time.time())},{'version':1,'running':True,'updated':int(time.time())-30}]:
                path.write_text(json.dumps(value));self.assertIsNone(proxy.service_status())
