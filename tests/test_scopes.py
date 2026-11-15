from support import install_test_catalogs
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import settings
from backend.service import VPN, Problem
from backend.catalog import PLATFORMS, valid_host, location_details


class ModeTests(unittest.TestCase):
    def test_host_rejects_multiple_trailing_dots(self):
        self.assertTrue(valid_host('vpn.example.com.'))
        self.assertFalse(valid_host('vpn.example.com..'))
        self.assertFalse(valid_host('vpn.example.com...'))

    def test_locations_expose_flag_and_country_name_separately(self):
        self.assertEqual(location_details('🇱🇹 Литва'),{'flag':'🇱🇹','location':'Литва'})
        self.assertEqual(location_details('Custom server'),{'flag':'','location':'Custom server'})
        germany=next(node for node in self.vpn.visible_nodes('telegram') if node['id']=='tg-eu')
        self.assertEqual(germany['flag'],'🇩🇪');self.assertEqual(germany['location'],'Германия')

    def setUp(self):
        install_test_catalogs(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = patch.multiple(settings, MODE='live', DB=Path(self.temp.name) / 'vpn.sqlite3')
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.vpn = VPN()

    def test_both_profiles_can_be_active_independently(self):
        device = self.vpn.issue(1, 'wg-eu')
        telegram = self.vpn.issue(1, 'tg-us', scope='telegram')
        self.assertEqual(self.vpn.status(1), device)
        self.assertEqual(self.vpn.status(1, 'telegram'), telegram)
        self.assertNotEqual(device['id'], telegram['id'])

    def test_revoke_device_preserves_telegram(self):
        self.vpn.issue(1, 'wg-eu')
        telegram = self.vpn.issue(1, 'tg-us', scope='telegram')
        self.vpn.revoke(1)
        self.assertEqual(self.vpn.status(1, 'telegram'), telegram)

    def test_revoke_telegram_preserves_device(self):
        device = self.vpn.issue(1, 'wg-eu')
        self.vpn.issue(1, 'tg-us', scope='telegram')
        self.vpn.revoke(1, scope='telegram')
        self.assertEqual(self.vpn.status(1), device)

    def test_switch_telegram_keeps_time_and_device_profile(self):
        device = self.vpn.issue(1, 'wg-eu')
        first = self.vpn.issue(1, 'tg-eu', scope='telegram')
        second = self.vpn.issue(1, 'tg-jp', expected=first['id'], expected_status='active', scope='telegram')
        self.assertEqual(first['expires'], second['expires'])
        self.assertEqual(second['node'], 'tg-jp')
        self.assertEqual(self.vpn.status(1), device)

    def test_servers_are_bound_to_their_mode(self):
        for node, scope in [('wg-eu','telegram'), ('tg-eu','device')]:
            with self.subTest(scope=scope), self.assertRaises(Problem):
                self.vpn.issue(1, node, scope=scope)
        self.assertEqual(self.vpn.status(1)['status'], 'none')
        self.assertEqual(self.vpn.status(1, 'telegram')['status'], 'none')

    def test_cross_mode_confirmation_cannot_revoke(self):
        device = self.vpn.issue(1, 'wg-eu')
        telegram = self.vpn.issue(1, 'tg-eu', scope='telegram')
        with self.assertRaises(Problem):
            self.vpn.revoke(1, expected=device['id'], scope='telegram')
        self.assertEqual(self.vpn.status(1, 'telegram'), telegram)


    def test_expiration_reconciles_both_modes(self):
        self.vpn.issue(1, 'wg-eu')
        self.vpn.issue(1, 'tg-eu', scope='telegram')
        with self.vpn.db() as db:
            db.execute('UPDATE profiles SET expires=?', (int(time.time()) - 1,))
        self.vpn.reconcile_once()
        with self.vpn.db() as db:
            self.assertEqual([r[0] for r in db.execute('SELECT state FROM profiles')], ['expired','expired'])


    def test_bad_platform_or_scope_is_rejected(self):
        for scope in ('vpn', '', [], None):
            with self.subTest(scope=scope), self.assertRaises(Problem):
                self.vpn.status(1, scope)
        self.vpn.issue(1, 'wg-eu')
        with self.assertRaises(Problem):
            self.vpn.connection(1, platform='unknown')

    def test_old_database_migrates_without_losing_profile(self):
        legacy_path = Path(self.temp.name) / 'legacy.sqlite3'
        with sqlite3.connect(legacy_path) as db:
            db.executescript("""
                CREATE TABLE profiles (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
                    node TEXT NOT NULL, address TEXT NOT NULL, private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE UNIQUE INDEX current_user ON profiles(user_id) WHERE state IN ('creating','active','revoking');
                CREATE UNIQUE INDEX current_address ON profiles(node,address) WHERE state IN ('creating','active','revoking');
            """)
            db.execute("INSERT INTO profiles VALUES (1,1,'wg-eu','10.77.0.2','','','active',?)", (int(time.time())+3600,))
        with patch.object(settings, 'DB', legacy_path):
            migrated = VPN(); migrated.reconcile_once()
            self.assertEqual(migrated.status(1)['id'], 1)
            migrated.issue(1, 'tg-eu', scope='telegram')
            self.assertEqual(migrated.status(1)['status'], 'active')
            self.assertEqual(migrated.status(1, 'telegram')['status'], 'active')
            restarted = VPN()
            self.assertEqual(restarted.status(1)['id'], 1)
