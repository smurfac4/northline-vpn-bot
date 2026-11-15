from support import install_test_catalogs
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

import settings
from backend import proxy,wireguard
from backend.admin import Admin
from backend.service import VPN,Problem


class PublicProxyTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        patcher=patch.multiple(settings,MODE='live',ROOT=self.root,DB=self.root/'profiles.db',ALLOW='*',ADMIN_IDS='10',
            NODES=self.root/'nodes.json',PROXY_NODES=self.root/'proxy.json',MTPROXY_NODE_ID='managed')
        patcher.start();self.addCleanup(patcher.stop)
        self.vpn=VPN();self.device=self.vpn.issue(10,'wg-eu')
        self.node=proxy.ProxyNode('pub-fi','Public Finland','8.8.8.8',8443,'FI','Финляндия','dd'+'ab'*16)
        self.vpn.catalogs['telegram']={self.node.id:self.node}
        live=patch.object(settings,'MODE','live');live.start();self.addCleanup(live.stop)
        self.admin=Admin(self.vpn)

    def issue(self):return self.vpn.issue(10,self.node.id,scope='telegram')

    def test_public_connection_needs_no_local_daemon_and_creates_no_personal_key(self):
        with patch('backend.proxy.service_status',return_value=None),patch('backend.proxy.sync') as sync:
            profile=self.issue();connection=self.vpn.connection(10,'telegram','ios')
        sync.assert_not_called()
        self.assertTrue(self.vpn.available('telegram'));self.assertEqual(profile['access_type'],'public')
        self.assertIn('secret='+self.node.secret,connection['connect_url']);self.assertIsNone(connection['download'])
        self.assertIn('не отключает',connection['notice'])
        self.assertEqual(self.vpn.current(10,'telegram')['private_key'],'')
        self.assertNotIn(self.node.secret,json.dumps(self.vpn.visible_nodes('telegram')))

    def test_revocation_removes_only_bot_profile_without_claiming_remote_key_revocation(self):
        profile=self.issue();device=self.vpn.status(10)
        with patch('backend.proxy.sync') as sync:
            result=self.admin.revoke(10,{'user_id':10,'scope':'telegram','expected_profile':profile['id'],'expected_status':'active'})
        sync.assert_not_called();self.assertIn('настройках Telegram',result['external_notice'])
        self.assertEqual(self.vpn.status(10),device)

    def test_public_proxy_cannot_claim_to_disconnect_shared_native_session(self):
        profile=self.issue()
        self.assertFalse(profile['session']['controllable'])
        with patch('backend.proxy.sync') as sync,self.assertRaises(Problem) as error:
            self.vpn.session(10,False,profile['id'],True)
        self.assertEqual(error.exception.status,409);sync.assert_not_called()
        self.assertEqual(self.vpn.status(10,'telegram'),profile)

    def test_public_profile_expires_and_reconciles_without_remote_control(self):
        self.issue()
        with self.vpn.db() as db:db.execute("UPDATE profiles SET expires=1 WHERE scope='telegram'")
        with patch('backend.proxy.sync') as sync:self.vpn.reconcile_once()
        sync.assert_not_called();self.assertEqual(self.vpn.status(10,'telegram')['status'],'expired')

    def test_public_health_checks_show_response_time_without_fake_traffic(self):
        with patch('backend.public_proxy.check',return_value=123.4):self.admin._check_public(self.node)
        server=next(row for row in self.admin.servers() if row['scope']=='telegram')
        self.assertEqual(server['metric_kind'],'availability');self.assertTrue(server['measurable'])
        self.assertEqual(server['metric']['latency_ms'],123.4);self.assertIsNone(server['metric']['download_mbps'])
        self.assertIsNone(server['metric']['peer_count'])

    def test_registry_hides_shared_secret_and_keeps_it_when_editing_name(self):
        row={'id':self.node.id,'name':'Finland','host':self.node.host,'port':8443,'secret':self.node.secret,'country':'FI','country_name':'Финляндия'}
        settings.PROXY_NODES.write_text(json.dumps([row]))
        catalog=self.admin.real_servers(10)['catalogs']['telegram']
        self.assertTrue(catalog['rows'][0]['has_secret']);self.assertNotIn('secret',catalog['rows'][0])
        public_row={k:v for k,v in catalog['rows'][0].items() if k not in ('profiles','has_secret')};public_row['name']='Updated'
        self.admin.edit_real_server(10,{'scope':'telegram','action':'save','original_id':self.node.id,'expected_revision':catalog['revision'],'server':public_row})
        self.assertEqual(proxy.parse_nodes(json.loads(settings.PROXY_NODES.read_text()))[self.node.id].secret,self.node.secret)
        self.assertNotIn(self.node.secret,json.dumps(self.admin.snapshot(10)))

    def test_browser_name_edit_preserves_verification_metadata_with_active_profiles(self):
        row={'id':self.node.id,'name':'Finland','host':self.node.host,'port':8443,
             'secret':self.node.secret,'country':'FI','country_name':'Финляндия','checked_at':int(time.time()),'latency_ms':75.5}
        settings.PROXY_NODES.write_text(json.dumps([row]))
        self.vpn.catalogs['telegram']=proxy.parse_nodes([row]);profile=self.issue()
        version=self.admin.real_servers(10)['catalogs']['telegram']['revision']
        browser={'id':self.node.id,'name':'Renamed','host':self.node.host,'port':8443,'enabled':True}
        self.admin.edit_real_server(10,{'scope':'telegram','action':'save','original_id':self.node.id,
            'expected_revision':version,'server':browser})
        saved=json.loads(settings.PROXY_NODES.read_text())[0]
        self.assertEqual(saved['checked_at'],row['checked_at'])
        self.assertEqual(saved['latency_ms'],row['latency_ms'])
        self.assertEqual(saved['secret'],self.node.secret)
        self.assertEqual(self.vpn.status(10,'telegram')['id'],profile['id'])

    def test_admin_shows_hourly_proxy_check_without_manual_measurement(self):
        from dataclasses import replace
        node=replace(self.node,checked_at=int(time.time()),latency_ms=75.5)
        self.vpn.catalogs['telegram'][node.id]=node
        with patch('time.time',return_value=node.checked_at+600):
            server=next(row for row in self.admin.servers() if row['id']==node.id)
        self.assertEqual(server['metric']['state'],'online')
        self.assertEqual(server['metric']['latency_ms'],75.5)
        self.assertIsNone(server['metric']['download_mbps'])

    def test_newer_failed_measurement_is_not_hidden_by_an_older_hourly_success(self):
        from dataclasses import replace
        node=replace(self.node,checked_at=int(time.time())-60,latency_ms=75.5)
        self.vpn.catalogs['telegram'][node.id]=node
        with patch('backend.public_proxy.check',side_effect=wireguard.WireGuardError('offline')):
            self.admin._check_public(node)
        server=next(row for row in self.admin.servers() if row['id']==node.id)
        self.assertEqual(server['metric']['state'],'unavailable')

    def test_secret_normalization_and_unsupported_values(self):
        import base64
        raw=bytes.fromhex('dd'+'ab'*16)
        self.assertEqual(proxy.normalize_secret(base64.urlsafe_b64encode(raw).decode().rstrip('=')),raw.hex())
        for value in ['',None,'invalid','dd12',123]:
            with self.subTest(value=value),self.assertRaises(ValueError):proxy.normalize_secret(value)

    def test_switching_to_a_full_managed_node_preserves_public_profile(self):
        managed=proxy.ProxyNode('managed','Managed','local.example.com',8443)
        self.vpn.catalogs['telegram'][managed.id]=managed
        with patch('backend.proxy.available',return_value=True),patch('backend.proxy.sync'):
            for user in range(1,17):self.vpn.issue(user,managed.id,scope='telegram')
            current=self.vpn.issue(20,self.node.id,scope='telegram')
            with self.assertRaises(Problem) as error:self.vpn.issue(20,managed.id,scope='telegram')
            self.assertEqual(error.exception.status,409)
            self.assertEqual(self.vpn.status(20,'telegram'),current)

    def test_public_probe_finds_docker_without_a_login_shell_and_keeps_secret_off_command_line(self):
        from backend import public_proxy
        result=Mock(stdout=json.dumps({'telegram_response':'resPQ','nonce_verified':True,'roundtrip_ms':55.5}))
        project=Path(__file__).resolve().parent.parent
        with patch.object(settings,'ROOT',project),patch('backend.public_proxy._public_ipv4',return_value='8.8.8.8'),patch('backend.public_proxy.shutil.which',return_value=None),patch('backend.public_proxy.Path.is_file',return_value=True),patch('backend.public_proxy.subprocess.run',return_value=result) as run:
            self.assertEqual(public_proxy.check(self.node),55.5)
        command=run.call_args_list[0].args[0]
        self.assertEqual(command[0],'/usr/local/bin/docker')
        self.assertNotIn(self.node.secret,' '.join(command))
        self.assertEqual(json.loads(run.call_args_list[0].kwargs['input'])['secret'],self.node.secret[2:])
