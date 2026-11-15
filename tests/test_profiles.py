from support import install_test_catalogs
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import settings
from backend.service import VPN, Problem


class ProfileLifecycleTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch = patch.multiple(settings, MODE='live', DB=Path(self.temp.name) / 'vpn.sqlite3')
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.vpn = VPN()

    def test_switch_preserves_expiry_and_revokes_old_profile(self):
        original = self.vpn.issue(1, 'wg-eu')
        switched = self.vpn.issue(1, 'wg-us')
        self.assertEqual(switched['node'], 'wg-us')
        self.assertEqual(switched['status'], 'active')
        self.assertEqual(switched['expires'], original['expires'])
        with self.vpn.db() as db:
            self.assertEqual(db.execute('SELECT state FROM profiles WHERE id=?', (original['id'],)).fetchone()[0], 'revoked')
            self.assertEqual(db.execute("SELECT COUNT(*) FROM profiles WHERE user_id=1 AND state='active'").fetchone()[0], 1)

    def test_duplicate_activation_is_idempotent(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            profiles = list(pool.map(lambda _: self.vpn.issue(1, 'wg-eu'), range(8)))
        self.assertEqual(len({p['id'] for p in profiles}), 1)

    def test_invalid_destination_keeps_current_profile(self):
        original = self.vpn.issue(1, 'wg-eu')
        with self.assertRaises(Problem):
            self.vpn.issue(1, 'missing')
        self.assertEqual(self.vpn.status(1), original)

    def test_revoke_and_reactivate(self):
        self.vpn.issue(1, 'wg-eu')
        self.assertEqual(self.vpn.revoke(1)['status'], 'revoked')
        self.assertEqual(self.vpn.revoke(1)['status'], 'revoked')
        self.assertEqual(self.vpn.issue(1, 'wg-jp')['status'], 'active')

    def test_history_cleanup_never_reuses_old_profile_ids(self):
        old=self.vpn.issue(1,'wg-eu');self.vpn.revoke(1)
        with self.vpn.db() as db:db.execute('DELETE FROM profiles')
        new=self.vpn.issue(1,'wg-eu')
        self.assertGreater(new['id'],old['id'])
        with self.assertRaises(Problem):self.vpn.revoke(1,old['id'],'active')
        self.assertEqual(self.vpn.status(1),new)

    def test_reconciliation_handles_profiles_removed_after_its_initial_read(self):
        self.vpn.issue(1,'wg-eu')
        with patch.object(self.vpn,'current',return_value=None):self.vpn.reconcile_once()

    def test_expired_profile_can_be_replaced(self):
        self.vpn.issue(1, 'wg-eu')
        with self.vpn.db() as db:
            db.execute('UPDATE profiles SET expires=? WHERE user_id=1', (int(time.time())-1,))
        self.assertEqual(self.vpn.status(1)['status'], 'expired')
        self.assertEqual(self.vpn.issue(1, 'wg-us')['status'], 'active')

    def test_profiles_are_isolated_between_users(self):
        self.vpn.issue(1, 'wg-eu')
        other = self.vpn.issue(2, 'wg-us')
        self.vpn.issue(1, 'wg-jp')
        self.vpn.revoke(1)
        self.assertEqual(self.vpn.status(2), other)

    def test_stale_confirmation_cannot_revoke_new_profile(self):
        first = self.vpn.issue(1, 'wg-eu', expected=0)
        second = self.vpn.issue(1, 'wg-us', expected=first['id'])
        with self.assertRaises(Problem) as error:
            self.vpn.revoke(1, expected=first['id'])
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(self.vpn.status(1), second)

    def test_stale_switch_cannot_replace_new_profile(self):
        first = self.vpn.issue(1, 'wg-eu', expected=0)
        second = self.vpn.issue(1, 'wg-us', expected=first['id'])
        with self.assertRaises(Problem):
            self.vpn.issue(1, 'wg-jp', expected=first['id'])
        self.assertEqual(self.vpn.status(1), second)

    def test_full_destination_preserves_existing_profile(self):
        original = self.vpn.issue(1, 'wg-eu')
        with self.vpn.db() as db:
            db.executemany(
                "INSERT INTO profiles (user_id,node,address,private_key,public_key,state,expires) VALUES (?,'wg-us',?,'','','active',?)",
                [(1000+i, str(ip), int(time.time())+3600)
                 for i, ip in enumerate(list(self.vpn.nodes['wg-us'].subnet.hosts())[1:])],
            )
        with self.assertRaises(Problem):
            self.vpn.issue(1, 'wg-us', expected=original['id'])
        self.assertEqual(self.vpn.status(1), original)

    def test_rejects_invalid_expected_profile(self):
        for value in (True, -1, '1', 1.5):
            with self.subTest(value=value), self.assertRaises(Problem):
                self.vpn.issue(1, 'wg-eu', expected=value)
        self.assertEqual(self.vpn.status(1)['status'], 'none')

    def test_confirmation_from_active_profile_cannot_recreate_revoked_access(self):
        original = self.vpn.issue(1, 'wg-eu')
        self.vpn.revoke(1)
        with self.assertRaises(Problem) as error:
            self.vpn.issue(1, 'wg-us', expected=original['id'], expected_status='active')
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(self.vpn.status(1)['status'], 'revoked')

    def test_permanent_profile_survives_time_and_keeps_confirmation_valid(self):
        original = self.vpn.issue(1, 'wg-eu')
        self.assertEqual(original['expires'],0); self.assertTrue(original['unlimited'])
        with patch('backend.service.time.time', return_value=time.time()+100*365*86400):
            self.vpn.reconcile_once()
            self.assertEqual(self.vpn.status(1),original)
            renewed = self.vpn.issue(1, 'wg-us', expected=original['id'], expected_status='active')
        self.assertEqual(renewed['status'], 'active')
        self.assertEqual(renewed['expires'],0)

    def test_permanent_access_migrates_existing_keys_once_without_reviving_revoked_profiles(self):
        original=self.vpn.issue(1,'wg-eu'); self.vpn.issue(2,'wg-us'); self.vpn.revoke(2)
        with self.vpn.db() as db:
            db.execute("DELETE FROM schema_migrations WHERE name='permanent-access-v1'")
            db.execute('UPDATE profiles SET expires=?',(int(time.time())+3600,))
        keys=dict(self.vpn.current(1)); migrated=VPN()
        self.assertEqual(migrated.status(1)['id'],original['id']); self.assertEqual(migrated.status(1)['expires'],0)
        self.assertEqual(migrated.current(1)['private_key'],keys['private_key'])
        self.assertEqual(migrated.status(2)['status'],'revoked')

    def test_invalid_status_is_rejected_without_mutation(self):
        for value in ('unknown', False, [], {}):
            with self.subTest(value=value), self.assertRaises(Problem) as error:
                self.vpn.issue(1, 'wg-eu', expected=0, expected_status=value)
            self.assertEqual(error.exception.status, 400)
        self.assertEqual(self.vpn.status(1)['status'], 'none')


if __name__ == '__main__':
    unittest.main()
