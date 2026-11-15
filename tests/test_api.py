from support import install_test_catalogs
import hmac
import tempfile
import time
import unittest
from urllib.parse import urlencode
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import run

import settings
from backend import main as backend_main
from backend.main import API, telegram_user
from backend.service import VPN, Problem


class RunScriptTests(unittest.TestCase):
    def test_start_does_not_scan_or_kill_other_processes(self):
        marker=Mock();marker.exists.return_value=False
        child=Mock();child.poll.return_value=0;child.returncode=0
        with patch.object(run.settings,'RESTART_FILE',marker),patch('run.signal.signal'),patch('run.subprocess.Popen',return_value=child),patch('run.os.popen') as scan,patch('run.os.kill') as kill:
            run.main()
        scan.assert_not_called();kill.assert_not_called()


class TelegramAuthTests(unittest.TestCase):
    def test_deeply_nested_signed_user_returns_unauthorized(self):
        fields = {'auth_date': str(int(time.time())), 'user': '[' * 2000 + '0' + ']' * 2000}
        message = '\n'.join(f'{key}={value}' for key, value in sorted(fields.items()))
        secret = hmac.digest(b'WebAppData', b'test-token', 'sha256')
        fields['hash'] = hmac.digest(secret, message.encode(), 'sha256').hex()
        with patch.object(settings, 'TOKEN', 'test-token'), self.assertRaises(Problem) as error:
            telegram_user(urlencode(fields))
        self.assertEqual(error.exception.status, 401)


class StartupRefreshTests(unittest.TestCase):
    def test_device_and_telegram_refreshes_are_independently_enabled(self):
        for device, telegram in ((True,False),(False,True),(False,False)):
            with self.subTest(device=device,telegram=telegram), patch.multiple(settings,MODE='live',TOKEN='token',BOT_KEY='internal',ALLOW='10',
                    PERSONAL_TEST=False,DEVICE_AUTO_UPDATE=device,PROXY_AUTO_UPDATE=telegram), patch.object(backend_main,'VPN'),patch.object(backend_main,'Admin'),patch.object(backend_main,'ThreadingHTTPServer'),patch.object(backend_main.os,'umask'),patch.object(backend_main.threading,'Thread') as thread,patch('builtins.print'):
                backend_main.main()
                names={call.kwargs.get('name') for call in thread.call_args_list}
                self.assertEqual('device-vpn-refresh' in names,device)
                self.assertEqual('proxy-refresh' in names,telegram)


class ApiModeTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = patch.multiple(settings, MODE='live', DB=Path(self.temp.name)/'api.sqlite3')
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.vpn = VPN()
        self.device = self.vpn.issue(1, 'wg-eu')
        self.telegram = self.vpn.issue(1, 'tg-eu', scope='telegram')

    def route(self, method, path, body=None):
        # Exercise the real route and service without binding a network socket.
        handler = object.__new__(API)
        handler.server = SimpleNamespace(vpn=self.vpn)
        handler.path, handler.command = path, method
        handler.actor = Mock(return_value=1)
        handler.body = Mock(return_value=body or {})
        handler.reply = Mock()
        handler.route()
        return handler.reply.call_args.args

    def test_head_requests_are_supported_for_web_app_bootstrapping(self):
        handler = object.__new__(API)
        handler.server = SimpleNamespace(vpn=self.vpn)
        handler.path, handler.command = '/', 'HEAD'
        handler.actor = Mock(return_value=1)
        handler.body = Mock(return_value={})
        handler.reply = Mock()
        handler.route()
        self.assertEqual(handler.reply.call_args.args[0], 200)

    def test_malformed_absolute_url_returns_bad_request(self):
        with self.assertRaises(Problem) as error:
            self.route('GET', 'http://[invalid/api/status')
        self.assertEqual(error.exception.status, 400)

    def test_conflicting_revoke_modes_do_not_touch_either_profile(self):
        before = self.vpn.statuses(1)
        with self.assertRaises(Problem) as error:
            self.route('POST','/api/revoke?scope=telegram',{'scope':'device'})
        self.assertEqual(error.exception.status, 400)
        self.assertEqual(self.vpn.statuses(1), before)

    def test_conflicting_issue_modes_are_rejected(self):
        before = self.vpn.statuses(1)
        with self.assertRaises(Problem):
            self.route('POST','/api/issue?scope=telegram',{'scope':'device','node':'wg-us'})
        self.assertEqual(self.vpn.statuses(1), before)

    def test_empty_and_duplicate_scope_are_rejected(self):
        for query in ('scope=', 'scope=device&scope=telegram'):
            with self.subTest(query=query), self.assertRaises(Problem) as error:
                self.route('GET','/api/status?'+query)
            self.assertEqual(error.exception.status, 400)

    def test_body_mode_works_without_query_for_compatibility(self):
        _, profile = self.route('POST','/api/issue',{'scope':'telegram','node':'tg-us'})
        self.assertEqual(profile['scope'], 'telegram')
        self.assertEqual(profile['node'], 'tg-us')
        self.assertEqual(self.vpn.status(1), self.device)

    def test_connection_is_bound_to_requested_profile(self):
        old = self.telegram
        self.vpn.issue(1,'tg-us',scope='telegram')
        with self.assertRaises(Problem) as error:
            self.route('GET', f'/api/connection?scope=telegram&expected_profile={old["id"]}&expected_status=active')
        self.assertEqual(error.exception.status, 409)

    def test_connection_is_bound_to_requested_state(self):
        self.vpn.revoke(1,scope='telegram')
        with self.assertRaises(Problem) as error:
            self.route('GET',f'/api/connection?scope=telegram&expected_profile={self.telegram["id"]}&expected_status=active')
        self.assertEqual(error.exception.status, 409)

    def test_matching_profile_returns_platform_specific_instructions(self):
        code, result = self.route('GET', f'/api/connection?scope=telegram&platform=windows&expected_profile={self.telegram["id"]}&expected_status=active')
        self.assertEqual(code, 200)
        self.assertEqual(result['platform'], 'windows')
        self.assertEqual(result['profile']['id'], self.telegram['id'])

    def test_invalid_expected_profile_is_a_client_error(self):
        for value in ('', '-1', 'one', '9'*30):
            with self.subTest(value=value), self.assertRaises(Problem) as error:
                self.route('GET','/api/connection?scope=telegram&expected_profile='+value)
            self.assertEqual(error.exception.status, 400)
