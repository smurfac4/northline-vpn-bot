import hmac
import html
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit
import settings
from backend.service import Problem, VPN
from backend.wireguard import WireGuardError
from backend.catalog import SCOPES, PLATFORMS
from backend.admin import Admin, is_admin
WEB = settings.ROOT / 'backend' / 'web'
STATIC = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/telegram-web-app.js': ('telegram-web-app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'), '/vpn-import.js': ('vpn-import.js', 'text/javascript; charset=utf-8'), '/vpn-import.css': ('vpn-import.css', 'text/css; charset=utf-8'), '/admin': ('admin.html', 'text/html; charset=utf-8'), '/admin/': ('admin.html', 'text/html; charset=utf-8'), '/admin.js': ('admin.js', 'text/javascript; charset=utf-8'), '/admin.css': ('admin.css', 'text/css; charset=utf-8')}

def telegram_user(raw):
    try:
        pairs = parse_qsl(raw, strict_parsing=True, max_num_fields=30)
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError
        received = fields.pop('hash')
        message = '\n'.join((f'{key}={value}' for (key, value) in sorted(fields.items())))
        secret = hmac.digest(b'WebAppData', settings.TOKEN.encode(), 'sha256')
        expected = hmac.digest(secret, message.encode(), 'sha256').hex()
        if not hmac.compare_digest(received, expected):
            raise ValueError
        age = time.time() - int(fields['auth_date'])
        user = json.loads(fields['user'])['id']
        if not -30 <= age <= 3600 or type(user) is not int or (not 0 < user < 2 ** 63):
            raise ValueError
        return user
    except (ValueError, KeyError, TypeError, RecursionError):
        raise Problem(401, 'Open the Mini App again from your Telegram bot.') from None

class API(BaseHTTPRequestHandler):

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def reply(self, code, data, content_type='application/json; charset=utf-8', headers=None):
        event = getattr(self, '_audit_event', None)
        if event and (not getattr(self, '_audit_logged', False)):
            self._audit_logged = True
            try:
                self.server.admin.observe(event['user'], event['identity'], event['source'], event['scope'], event['action'], event.get('node', ''), code, (time.monotonic() - event['started']) * 1000)
            except (OSError, sqlite3.Error):
                print('Request audit could not be saved.', flush=True)
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        for (name, value) in (headers or {}).items():
            self.send_header(name, value)
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' https://telegram.org; object-src 'none'; base-uri 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def actor(self):
        bot_key = self.headers.get('X-Bot-Key')
        if bot_key and settings.BOT_KEY and hmac.compare_digest(bot_key.encode(), settings.BOT_KEY.encode()):
            uid = self.headers.get('X-Telegram-User', '')
            if uid.isascii() and uid.isdigit() and (len(uid) < 20) and (0 < int(uid) < 2 ** 63):
                self._request_source = 'bot'
                self._identity = {}
                try:
                    identity = json.loads(self.headers.get('X-Telegram-Profile', '{}'))
                    if isinstance(identity, dict) and identity.get('id') == int(uid):
                        self._identity = identity
                except (ValueError, TypeError):
                    pass
                return int(uid)
            raise Problem(400, 'Invalid Telegram user.')
        data = self.headers.get('X-Telegram-Init-Data', '')
        if settings.TOKEN and data:
            user = telegram_user(data)
            self._request_source = 'miniapp'
            self._identity = json.loads(dict(parse_qsl(data))['user'])
            return user
        raise Problem(401, 'Open this app from your Telegram bot.')

    def body(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                raise ValueError
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError
            return data
        except TimeoutError:
            raise Problem(408, 'Время загрузки запроса истекло. Повторите действие.') from None
        except (ValueError, UnicodeError, RecursionError):
            raise Problem(400, 'Некорректное тело запроса.') from None

    def route(self):
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            raise Problem(400, 'Некорректный адрес запроса.') from None
        path = parsed.path
        try:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=30)
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError
        except ValueError:
            raise Problem(400, 'Некорректные параметры запроса.') from None
        method = self.command
        read_methods = {'GET', 'HEAD'}
        vpn = self.server.vpn
        if method in read_methods and path in STATIC:
            (filename, mime) = STATIC[path]
            return self.reply(200, (WEB / filename).read_bytes(), mime)
        if method in read_methods and path == '/health':
            return self.reply(200, {'ok': True, 'service': 'northline'})
        if method in read_methods and path.startswith('/connect-import/'):
            token = path.removeprefix('/connect-import/')
            (filename, _) = vpn.import_file(token)
            if not filename.endswith('.ovpn'):
                raise Problem(404, 'Для этого профиля используйте импорт файла в WireGuard.')
            page = (WEB / 'vpn-import.html').read_text().replace('__CONFIG_PATH__', html.escape('/connect-config/' + token, quote=True))
            return self.reply(200, page.encode(), 'text/html; charset=utf-8')
        if method in read_methods and path.startswith('/connect-config/'):
            (filename, content) = vpn.import_file(path.removeprefix('/connect-config/'))
            return self.reply(200, content.encode(), 'application/x-openvpn-profile' if filename.endswith('.ovpn') else 'application/octet-stream', {'Content-Disposition': 'attachment; filename="' + filename + '"', 'Access-Control-Allow-Origin': '*'})
        if not path.startswith('/api/'):
            raise Problem(404, 'Not found.')
        user = self.actor()
        if hasattr(self.server, 'admin'):
            self._audit_event = {'user': user, 'identity': getattr(self, '_identity', {}), 'source': getattr(self, '_request_source', 'local'), 'scope': query.get('scope', 'device'), 'action': path.removeprefix('/api/'), 'started': time.monotonic()}
        if path.startswith('/api/admin/'):
            admin = self.server.admin
            self._audit_event['scope'] = 'admin'
            admin.require(user)
            if method == 'GET' and path == '/api/admin/snapshot':
                return self.reply(200, admin.snapshot(user))
            if method == 'GET' and path == '/api/admin/registry':
                return self.reply(200, admin.real_servers(user))
            actions = {'/api/admin/registry': admin.edit_real_server, '/api/admin/server': admin.server_policy, '/api/admin/account': admin.account_policy, '/api/admin/revoke': admin.revoke, '/api/admin/measure': admin.measure, '/api/admin/restart': admin.restart}
            if method == 'POST' and path in actions:
                body = self.body()
                if body.get('scope') in ('device', 'telegram'):
                    self._audit_event['scope'] = body['scope']
                if isinstance(body.get('node'), str):
                    self._audit_event['node'] = body['node']
                result = actions[path](user, body)
                self.reply(200, result)
                if result.get('restart_required'):
                    admin.request_restart()
                return
            raise Problem(404, 'Раздел админки не найден.')
        scope = vpn.validate_scope(query.get('scope', 'device'))
        if method == 'POST' and path == '/api/telemetry':
            if getattr(self, '_request_source', '') != 'bot':
                raise Problem(403, 'Запись событий чата доступна только боту.')
            body = self.body()
            scope = self.request_scope(query, body)
            allowed = {'start', 'menu', 'id', 'device', 'telegram', 'servers', 'select', 'issue', 'status', 'confirm-revoke', 'revoke', 'setup', 'config', 'export', 'help', 'guide', 'sticker', 'admin', 'home', 'app', 'message'}
            action = body.get('action')
            if not isinstance(action, str) or not action.startswith('chat/') or action[5:] not in allowed:
                raise Problem(400, 'Некорректное событие чата.')
            if hasattr(self, '_audit_event'):
                self._audit_event['action'] = action
            return self.reply(200, {'ok': True})
        if method in read_methods and path == '/api/status':
            profiles = vpn.statuses(user)
            return self.reply(200, {'mode': 'live', 'hours': settings.TRIAL_HOURS, 'unlimited': True, 'personal_test': settings.PERSONAL_TEST, 'scope': scope, 'available': vpn.available(scope), 'scopes': SCOPES, 'platforms': PLATFORMS, 'nodes': vpn.visible_nodes(scope, user), 'live_access': vpn.live_access(user), 'is_admin': is_admin(user), 'profile': profiles[scope], 'profiles': profiles})
        if method == 'POST' and path == '/api/issue':
            body = self.body()
            scope = self.request_scope(query, body)
            return self.reply(200, vpn.issue(user, body.get('node'), body.get('expected_profile'), body.get('expected_status'), scope))
        if method == 'POST' and path == '/api/revoke':
            body = self.body()
            scope = self.request_scope(query, body)
            return self.reply(200, vpn.revoke(user, body.get('expected_profile'), body.get('expected_status'), scope))
        if method == 'POST' and path == '/api/session':
            body = self.body()
            scope = self.request_scope(query, body)
            return self.reply(200, vpn.session(user, body.get('enabled'), body.get('expected_profile'), body.get('expected_enabled'), scope))
        if method in read_methods and path == '/api/config':
            return self.reply(200, {'config': vpn.config(user, scope)})
        if method in read_methods and path == '/api/connection':
            expected = query.get('expected_profile')
            if expected is not None:
                if not expected.isascii() or not expected.isdigit() or len(expected) > 19:
                    raise Problem(400, 'Некорректный номер профиля.')
                expected = int(expected)
            return self.reply(200, vpn.connection(user, scope, query.get('platform', 'other'), expected, query.get('expected_status')))
        raise Problem(404, 'Not found.')

    def request_scope(self, query, body):
        if 'scope' in query and 'scope' in body and (query['scope'] != body['scope']):
            raise Problem(400, 'Режим в адресе запроса не совпадает с выбранным режимом.')
        scope = self.server.vpn.validate_scope(body.get('scope', query.get('scope', 'device')))
        if hasattr(self, '_audit_event'):
            self._audit_event['scope'] = scope
            self._audit_event['node'] = body.get('node', '') if isinstance(body.get('node', ''), str) else ''
        return scope

    def log_message(self, format, *args):
        try:
            if any((prefix in getattr(self, 'path', '') for prefix in ('/connect-config/', '/connect-import/'))):
                return super().log_message('Configuration import: %s', getattr(self, 'command', 'GET'))
            super().log_message(format, *args)
        except OSError:
            pass

    def handle_request(self):
        try:
            self.route()
        except Problem as error:
            self.reply(error.status, {'error': error.message})
        except WireGuardError:
            self.reply(503, {'error': 'VPN-сервер временно недоступен. Обновите состояние и повторите попытку.'})
        except (BrokenPipeError, ConnectionResetError):
            return
        except sqlite3.Error:
            self.reply(503, {'error': 'База данных временно недоступна. Повторите запрос.'})
        except OSError:
            self.reply(503, {'error': 'Не удалось прочитать или записать данные сервиса. Повторите запрос.'})
    do_GET = handle_request
    do_HEAD = handle_request
    do_POST = handle_request

def main():
    os.umask(63)
    if not settings.TOKEN or not settings.BOT_KEY or (not settings.ALLOW):
        raise SystemExit('Live mode requires BOT_TOKEN, BOT_API_KEY and ALLOWED_TELEGRAM_IDS.')
    if settings.PERSONAL_TEST and settings.personal_test_owner() is None:
        raise SystemExit('Personal live tests require exactly one allowed administrator account.')
    with ThreadingHTTPServer(('127.0.0.1', settings.PORT), API) as server:
        server.vpn = VPN()
        server.admin = Admin(server.vpn)
        threading.Thread(target=server.vpn.reconcile, daemon=True).start()
        if settings.DEVICE_AUTO_UPDATE:
            from backend.device_refresh import maintain as maintain_device_vpn
            threading.Thread(target=maintain_device_vpn, args=(server.vpn,), name='device-vpn-refresh', daemon=True).start()
        if settings.PROXY_AUTO_UPDATE:
            from backend.proxy_refresh import maintain
            threading.Thread(target=maintain, args=(server.vpn,), name='proxy-refresh', daemon=True).start()
        if settings.PERSONAL_TEST:
            from backend.local_maintenance import maintain as maintain_local
            threading.Thread(target=maintain_local, args=(server.vpn,), name='local-port-renewal', daemon=True).start()
        print(f"Mini App: http://127.0.0.1:{settings.PORT} ({'live'})", flush=True)
        server.serve_forever()
if __name__ == '__main__':
    main()
