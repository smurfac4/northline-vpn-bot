from support import install_test_catalogs
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import settings
from backend.clients import client_for
from backend.main import API
from backend.service import Problem, VPN


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        config = patch.multiple(settings, MODE='live', DB=root/'vpn.sqlite3', DEVICE_NODES=root/'device.json', ALLOW='*')
        config.start(); self.addCleanup(config.stop)
        self.vpn = VPN()
        self.profile = self.vpn.issue(10, 'wg-eu')
        live = patch.object(settings, 'MODE', 'live'); live.start(); self.addCleanup(live.stop)
        render = patch('backend.wireguard.client_config', return_value='[Interface]\nPrivateKey = test\n')
        render.start(); self.addCleanup(render.stop)

    def token(self):
        return self.vpn.connection(10, 'device', 'ios')['download_url'].rsplit('/', 1)[1]

    def test_capability_download_works_without_telegram_headers_and_sends_no_credentials(self):
        token = self.token()
        handler = object.__new__(API)
        handler.server = SimpleNamespace(vpn=self.vpn)
        handler.path = '/connect-config/' + token; handler.command = 'GET'
        handler.actor = Mock(side_effect=AssertionError('Native import has no Telegram auth headers'))
        handler.reply = Mock()
        handler.route()
        handler.actor.assert_not_called()
        code, data, mime, headers = handler.reply.call_args.args
        self.assertEqual(code, 200); self.assertIn(b'PrivateKey = test', data)
        self.assertIn('northline-vpn.conf', headers['Content-Disposition'])
        self.assertNotIn('test', token)

    def test_expired_tampered_and_previous_process_links_are_rejected(self):
        token = self.token()
        for bad in (token+'x', token.replace('.', 'x', 1), 'bad', 'é.bad'):
            with self.subTest(token=bad), self.assertRaises(Problem): self.vpn.import_file(bad)
        with patch('backend.service.time.time', return_value=time.time()+301), self.assertRaises(Problem): self.vpn.import_file(token)
        with patch.object(settings, 'MODE', 'live'):
            another = VPN()
        with self.assertRaises(Problem): another.import_file(token)

    def test_links_stop_working_after_revoke_or_profile_replacement(self):
        token = self.token()
        with patch.object(settings, 'MODE', 'live'):
            self.vpn.revoke(10)
        with self.assertRaises(Problem): self.vpn.import_file(token)
        with patch.object(settings, 'MODE', 'live'):
            self.vpn.issue(10, 'wg-us')
        with self.assertRaises(Problem): self.vpn.import_file(token)

    def test_permission_denial_block_and_expiry_prevent_config_export(self):
        token = self.token()
        with patch.object(settings, 'ALLOW', '20'), self.assertRaises(Problem): self.vpn.import_file(token)
        with self.vpn.db() as db:
            db.execute('INSERT INTO accounts(user_id,first_seen,last_seen,blocked) VALUES (10,1,1,1)')
        with self.assertRaises(Problem): self.vpn.import_file(token)
        with self.vpn.db() as db:
            db.execute('UPDATE accounts SET blocked=0'); db.execute('UPDATE profiles SET expires=1')
        with self.assertRaises(Problem): self.vpn.import_file(token)

    def test_client_metadata_uses_platform_and_actual_protocol(self):
        connection = self.vpn.connection(10, 'device', 'ios')
        self.assertEqual(connection['client']['name'], 'WireGuard')
        self.assertFalse(connection['client']['native_import'])
        self.assertIn('id1441195209', connection['client']['install_url'])
        self.assertTrue(client_for('OpenVPN', 'ios')['native_import'])
        self.assertIn('net.openvpn.openvpn', client_for('OpenVPN', 'android')['install_url'])
        self.assertFalse(client_for('OpenVPN', 'linux')['native_import'])
        self.assertIsNone(client_for('WireGuard', 'windows')['open_url'])

    def test_ios_launch_uses_native_link_and_import_escapes_the_miniapp_webview(self):
        client = client_for('OpenVPN', 'ios')
        self.assertEqual(client['open_url'], 'openvpn://')
        self.assertFalse(client['open_via_store']); self.assertTrue(client['external_import'])
        self.assertFalse(client_for('OpenVPN', 'android')['external_import'])

    def test_import_page_preserves_capability_and_never_embeds_private_config(self):
        token = self.token(); handler = object.__new__(API)
        handler.server = SimpleNamespace(vpn=self.vpn)
        handler.path = '/connect-import/'+token; handler.command = 'GET'
        handler.actor = Mock(side_effect=AssertionError('Browser handoff has no Telegram headers'))
        handler.reply = Mock()
        with patch.object(self.vpn, 'import_file', return_value=('northline-vpn.ovpn', 'PRIVATE CONFIG')) as validate:
            handler.route()
        validate.assert_called_once_with(token); handler.actor.assert_not_called()
        code, body, mime = handler.reply.call_args.args
        self.assertEqual(code, 200); self.assertIn('text/html', mime)
        self.assertIn(('/connect-config/'+token).encode(), body)
        self.assertIn(b'vpn-import.js', body); self.assertNotIn(b'PRIVATE CONFIG', body)
        self.assertIn(b'no-referrer', body)
        with patch('backend.service.time.time', return_value=time.time()+301), self.assertRaises(Problem): handler.route()

    def test_wireguard_config_is_not_presented_as_openvpn_import(self):
        token=self.token(); handler=object.__new__(API)
        handler.server=SimpleNamespace(vpn=self.vpn); handler.path='/connect-import/'+token; handler.command='GET'
        with self.assertRaises(Problem) as error:handler.route()
        self.assertEqual(error.exception.status,404)

    def test_import_capability_is_redacted_in_http_logs(self):
        token = self.token(); handler = object.__new__(API)
        handler.command = 'GET'
        for prefix in ('/connect-config/','/connect-import/'):
            handler.path = prefix+token
            with self.subTest(prefix=prefix), patch('http.server.BaseHTTPRequestHandler.log_message') as log:
                handler.log_message('request %s', handler.path)
            self.assertNotIn(token, str(log.call_args))
