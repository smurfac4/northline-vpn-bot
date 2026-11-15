from support import install_test_catalogs
import json
from dataclasses import replace
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import settings
from backend.admin import Admin, is_admin
from backend.main import API
from backend.service import VPN, Problem


class AdminTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.env=self.root/'.env'; self.env.write_text('VPN_MODE=live\nPRESERVED=value\n')
        self.config=patch.multiple(settings,MODE='live',DB=self.root/'vpn.sqlite3',ADMIN_IDS='10',
                                  ENV_FILE=self.env,RESTART_FILE=self.root/'restart.request')
        self.config.start();self.addCleanup(self.config.stop)
        self.vpn=VPN();self.admin=Admin(self.vpn)
        self.admin.observe(20,{'id':20,'first_name':'Тест','username':'example'},'bot','device','status','',200,5)

    def test_permissions_fail_closed(self):
        for user in (20,0,True):
            with self.subTest(user=user),self.assertRaises(Problem) as error:self.admin.snapshot(user)
            self.assertEqual(error.exception.status,403)
        with patch.object(settings,'ADMIN_IDS',''):
            self.assertFalse(is_admin(10))

    def test_legacy_accounts_migrate_without_changing_existing_blocks(self):
        legacy=self.root/'legacy.sqlite3'
        with sqlite3.connect(legacy) as db:
            db.execute("CREATE TABLE accounts (user_id INTEGER PRIMARY KEY, username TEXT DEFAULT '',first_name TEXT DEFAULT '',last_name TEXT DEFAULT '',first_seen INTEGER,last_seen INTEGER,blocked INTEGER DEFAULT 0)")
            db.execute('INSERT INTO accounts(user_id,first_seen,last_seen,blocked) VALUES (20,1,2,1)')
        with patch.multiple(settings,DB=legacy,ALLOW='10'):
            migrated=VPN()
            with migrated.db() as db:row=db.execute('SELECT * FROM accounts WHERE user_id=20').fetchone()
            self.assertEqual(row['blocked'],1);self.assertIsNone(row['live_device']);self.assertIsNone(row['live_telegram'])
            self.assertFalse(migrated.live_access(20)['telegram']['allowed'])

    def test_admin_api_checks_role_before_mutation(self):
        handler=object.__new__(API);handler.server=SimpleNamespace(vpn=self.vpn,admin=self.admin)
        handler.path='/api/admin/server';handler.command='POST';handler.actor=Mock(return_value=20)
        handler.body=Mock(return_value={'scope':'device','node':'wg-eu','maintenance':True})
        with self.assertRaises(Problem) as error:handler.route()
        self.assertEqual(error.exception.status,403);handler.body.assert_not_called()
        self.assertFalse(self.vpn.visible_nodes('device')[0]['maintenance'])

    def test_snapshot_contains_usage_and_no_credentials(self):
        self.vpn.issue(20,'wg-eu');self.vpn.issue(20,'tg-us',scope='telegram')
        self.admin.observe(20,{},'miniapp','telegram','issue','tg-us',200,12)
        snapshot=self.admin.snapshot(10)
        account=next(user for user in snapshot['users'] if user['user_id']==20)
        self.assertEqual(account['profiles']['device']['node'],'wg-eu')
        self.assertEqual(account['profiles']['telegram']['node'],'tg-us')
        self.assertEqual(account['username'],'example');self.assertEqual(account['requests_24h'],2)
        serialized=json.dumps(snapshot)
        for forbidden in ('private_key','BOT_TOKEN','BOT_API_KEY','preshared_key'):
            self.assertNotIn(forbidden,serialized)
        self.assertEqual(len(snapshot['servers']),32)
        self.assertTrue(all(row['metric']['state']=='unknown' for row in snapshot['servers']))

    def test_identity_removal_updates_account_but_missing_identity_preserves_it(self):
        self.admin.observe(20,{},'miniapp','device','status','',200,1)
        self.admin.observe(20,{'id':20,'first_name':'New'},'bot','device','status','',200,1)
        account=self.admin.snapshot(10)['users'][0]
        self.assertEqual(account['first_name'],'New');self.assertEqual(account['username'],'')

    def test_maintenance_blocks_new_access_but_preserves_existing_profiles(self):
        current=self.vpn.issue(20,'wg-eu')
        self.admin.server_policy(10,{'scope':'device','node':'wg-eu','maintenance':True,'note':'Проверка'})
        with self.assertRaises(Problem):self.vpn.issue(21,'wg-eu')
        self.assertEqual(self.vpn.issue(20,'wg-eu'),current)
        self.assertEqual(self.vpn.status(20),current)
        self.admin.server_policy(10,{'scope':'device','node':'wg-eu','maintenance':False})
        self.assertEqual(self.vpn.issue(21,'wg-eu')['status'],'active')

    def test_block_account_prevents_new_profiles_and_switching_but_not_revocation(self):
        profile=self.vpn.issue(20,'wg-eu')
        self.admin.account_policy(10,{'user_id':20,'blocked':True})
        for node,scope in [('wg-us','device'),('tg-us','telegram')]:
            with self.subTest(scope=scope),self.assertRaises(Problem) as error:self.vpn.issue(20,node,scope=scope)
            self.assertEqual(error.exception.status,403)
        self.assertEqual(self.vpn.status(20),profile)
        self.assertEqual(self.vpn.revoke(20)['status'],'revoked')
        self.admin.account_policy(10,{'user_id':20,'blocked':False})
        self.assertEqual(self.vpn.issue(20,'tg-us',scope='telegram')['status'],'active')

    def test_admin_cannot_block_self(self):
        with self.assertRaises(Problem):self.admin.account_policy(10,{'user_id':10,'blocked':True})

    def test_access_policy_is_persistent_scoped_and_cannot_grant_admin_role(self):
        with patch.object(settings,'ALLOW','10'):
            self.admin.account_policy(10,{'user_id':20,'scope':'device','live_access':True})
            restarted=VPN()
            self.assertTrue(restarted.live_access(20)['device']['allowed'])
            self.assertFalse(restarted.live_access(20)['telegram']['allowed'])
            self.assertFalse(is_admin(20))
            self.admin.account_policy(10,{'user_id':20,'blocked':True})
            with patch.object(settings,'MODE','live'),self.assertRaises(Problem) as error:restarted.issue(20,'wg-eu')
            self.assertEqual(error.exception.status,403)

    def test_access_policy_rejects_self_service_invalid_fields_and_admin_lockout(self):
        for actor,body,status in [(20,{'user_id':20,'scope':'telegram','live_access':True},403),
            (10,{'user_id':10,'scope':'telegram','live_access':False},409),
            (10,{'user_id':20,'scope':'invalid','live_access':True},400),
            (10,{'user_id':20,'scope':'telegram','live_access':1},400),
            (10,{'user_id':20,'scope':'telegram','live_access':True,'blocked':False},400),
            (10,{'user_id':99,'scope':'telegram','live_access':True},404)]:
            with self.subTest(actor=actor,body=body),self.assertRaises(Problem) as error:self.admin.account_policy(actor,body)
            self.assertEqual(error.exception.status,status)

    def test_admin_revocation_is_scoped_and_checks_version(self):
        device=self.vpn.issue(20,'wg-eu');telegram=self.vpn.issue(20,'tg-us',scope='telegram')
        with self.assertRaises(Problem):self.admin.revoke(10,{'user_id':20,'scope':'telegram','expected_profile':device['id']})
        self.admin.revoke(10,{'user_id':20,'scope':'telegram','expected_profile':telegram['id'],'expected_status':'active'})
        self.assertEqual(self.vpn.status(20),device)
        self.assertEqual(self.vpn.status(20,'telegram')['status'],'revoked')
        self.assertEqual(self.admin.snapshot(10)['audit'][0]['action'],'profile_revoked')

    def test_single_click_samples_twice_and_stays_pending_between_samples(self):
        key=('device','wg-eu');self.admin.pending.add(key)
        samples=[json.dumps({'rx_bytes':1000,'tx_bytes':2000,'peer_count':1}),json.dumps({'rx_bytes':5001000,'tx_bytes':10002000,'peer_count':1})]
        def pause(seconds):
            self.assertEqual(seconds,10);self.assertIn(key,self.admin.pending)
        with patch('backend.admin.wg.control',side_effect=samples) as read,patch('backend.admin.time.time',side_effect=[100,110]),patch('backend.admin.time.sleep',side_effect=pause):
            self.admin._measure_window(*key,self.vpn.nodes['wg-eu'])
        self.assertEqual(read.call_count,2);self.assertNotIn(key,self.admin.pending)
        with self.vpn.db() as db:row=db.execute('SELECT * FROM server_metrics').fetchone()
        self.assertEqual(row['download_mbps'],8);self.assertEqual(row['upload_mbps'],4)

    def test_unavailable_measurement_clears_pending_without_waiting(self):
        key=('device','wg-eu');self.admin.pending.add(key)
        with patch.object(self.admin,'_probe',return_value=False),patch('backend.admin.time.sleep') as pause:
            self.admin._measure_window(*key,self.vpn.nodes['wg-eu'])
        pause.assert_not_called();self.assertNotIn(key,self.admin.pending)

    def test_display_name_change_during_measurement_does_not_drop_the_result(self):
        node=self.vpn.nodes['wg-eu']
        def read(*args):
            self.vpn.nodes['wg-eu']=replace(node,name='Updated',country='LT',country_name='Литва')
            return json.dumps({'rx_bytes':100,'tx_bytes':200,'peer_count':0})
        with patch('backend.admin.wg.control',side_effect=read):
            self.assertTrue(self.admin._probe('device','wg-eu',node))
        with self.vpn.db() as db:row=db.execute('SELECT * FROM server_metrics').fetchone()
        self.assertEqual(row['state'],'online')

    def test_live_probe_uses_counter_deltas_and_handles_reset(self):
        with patch.object(settings,'MODE','live'),patch('backend.admin.wg.control',return_value=json.dumps({'rx_bytes':1000000,'tx_bytes':2000000,'peer_count':2})),patch('backend.admin.time.time',return_value=100):
            self.admin._probe('device','wg-eu')
        with patch.object(settings,'MODE','live'),patch('backend.admin.wg.control',return_value=json.dumps({'rx_bytes':6000000,'tx_bytes':12000000,'peer_count':2})),patch('backend.admin.time.time',return_value=110):
            self.admin._probe('device','wg-eu')
        with self.vpn.db() as db:metric=db.execute('SELECT * FROM server_metrics').fetchone()
        self.assertEqual(metric['download_mbps'],8);self.assertEqual(metric['upload_mbps'],4)
        with patch.object(settings,'MODE','live'),patch('backend.admin.wg.control',return_value=json.dumps({'rx_bytes':1,'tx_bytes':1,'peer_count':0})),patch('backend.admin.time.time',return_value=120):
            self.admin._probe('device','wg-eu')
        with self.vpn.db() as db:metric=db.execute('SELECT * FROM server_metrics').fetchone()
        self.assertIsNone(metric['download_mbps'])

    def test_probe_failure_is_visible_without_raw_error_details(self):
        from backend.wireguard import WireGuardError
        with patch('backend.admin.wg.control',side_effect=WireGuardError('secret details')):
            self.admin._probe('device','wg-eu')
        with self.vpn.db() as db:metric=db.execute('SELECT * FROM server_metrics').fetchone()
        self.assertEqual(metric['state'],'unavailable');self.assertNotIn('secret',metric['note'])

    def test_restart_requires_admin_and_confirmation(self):
        for actor,body in [(20,{'confirm':True}),(10,{'confirm':False})]:
            with self.subTest(actor=actor),self.assertRaises(Problem):self.admin.restart(actor,body)
        with patch.dict(os.environ,{'NORTHLINE_SUPERVISED':'1'}):
            result=self.admin.restart(10,{'confirm':True})
        self.assertEqual(result['previous_runtime_id'],self.admin.runtime_id)
        self.assertTrue(result['restart_required'])

    def test_request_retention_limit_is_exact(self):
        import time
        now=int(time.time())
        with self.vpn.db() as db:
            db.executemany('INSERT INTO request_events(created,user_id,source,scope,action,status_code,duration_ms) VALUES (?,?,?,?,?,?,?)',
                           [(now,20,'bot','device','status',200,1)]*30001)
        self.admin.observe(20,{},'bot','device','status','',200,1)
        with self.vpn.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM request_events').fetchone()[0],30000)

    def test_chat_telemetry_cannot_be_written_by_mini_app(self):
        handler=object.__new__(API);handler.server=SimpleNamespace(vpn=self.vpn,admin=self.admin)
        handler.path='/api/telemetry';handler.command='POST';handler.actor=Mock(return_value=20)
        handler._request_source='miniapp';handler.body=Mock(return_value={'action':'chat/help'});handler.reply=Mock()
        with self.assertRaises(Problem) as error:handler.route()
        self.assertEqual(error.exception.status,403)

    def test_chat_telemetry_accepts_only_known_actions_from_bot(self):
        handler=object.__new__(API);handler.server=SimpleNamespace(vpn=self.vpn,admin=self.admin)
        handler.path='/api/telemetry?scope=telegram';handler.command='POST';handler.actor=Mock(return_value=20)
        handler._request_source='bot';handler.body=Mock(return_value={'action':'chat/help','scope':'telegram'});handler.reply=Mock()
        handler.route()
        self.assertEqual(handler._audit_event['action'],'chat/help')
        self.assertEqual(handler._audit_event['scope'],'telegram')
        handler.body.return_value={'action':'chat/private-message-with-secret','scope':'telegram'}
        with self.assertRaises(Problem):handler.route()
