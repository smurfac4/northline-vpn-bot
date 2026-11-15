"""Private administration, request audit and connection telemetry."""
import hashlib
import json
import os
import secrets
import sqlite3
import shutil
import threading
import time
from urllib.parse import urlsplit
import settings
from backend.catalog import SCOPES, node_display_name
from backend.service import Problem
from backend import wireguard as wg, proxy, public_proxy, device_vpn
from backend.registry import Registry

def is_admin(user):
    return type(user) is int and str(user) in {item.strip() for item in settings.ADMIN_IDS.split(',') if item.strip()}

class Admin:

    def __init__(self, vpn):
        self.vpn = vpn
        self.registry = Registry(vpn)
        self.runtime_id = secrets.token_hex(8)
        self.pending = set()
        self.probe_lock = threading.Lock()
        with vpn.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS request_events (
                    id INTEGER PRIMARY KEY, created INTEGER NOT NULL, user_id INTEGER NOT NULL,
                    source TEXT NOT NULL, scope TEXT NOT NULL, action TEXT NOT NULL,
                    node TEXT NOT NULL DEFAULT '', status_code INTEGER NOT NULL, duration_ms REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS event_time ON request_events(created);
                CREATE INDEX IF NOT EXISTS event_user ON request_events(user_id,created);
                CREATE TABLE IF NOT EXISTS admin_audit (
                    id INTEGER PRIMARY KEY, created INTEGER NOT NULL, actor INTEGER NOT NULL,
                    action TEXT NOT NULL, target TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS server_metrics (
                    scope TEXT NOT NULL, node TEXT NOT NULL, sampled_at INTEGER NOT NULL,
                    state TEXT NOT NULL, latency_ms REAL, rx_bytes INTEGER, tx_bytes INTEGER,
                    download_mbps REAL, upload_mbps REAL, peer_count INTEGER, note TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(scope,node)
                );
            """)
            columns = {row['name'] for row in db.execute('PRAGMA table_info(server_metrics)')}
            if 'sample_id' not in columns:
                db.execute('ALTER TABLE server_metrics ADD COLUMN sample_id TEXT')
            db.execute("""INSERT OR IGNORE INTO accounts(user_id,first_seen,last_seen)
                SELECT user_id,MIN(CASE WHEN expires>0 THEN expires-86400 ELSE ? END),
                MAX(CASE WHEN expires>0 THEN expires-86400 ELSE ? END) FROM profiles GROUP BY user_id""", (int(time.time()), int(time.time())))

    def require(self, user):
        if not is_admin(user):
            raise Problem(403, 'Доступ к админке разрешён только администратору.')

    def observe(self, user, identity, source, scope, action, node, status, duration):
        now = int(time.time())
        identity = identity if isinstance(identity, dict) else {}
        complete = int(identity.get('id') == user and 'first_name' in identity)
        values = [str(identity.get(key) or '')[:80] for key in ('username', 'first_name', 'last_name')]
        with self.vpn.db() as db:
            db.execute("""INSERT INTO accounts(user_id,username,first_name,last_name,first_seen,last_seen)
                VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                username=CASE WHEN ? THEN excluded.username ELSE accounts.username END,
                first_name=CASE WHEN ? THEN excluded.first_name ELSE accounts.first_name END,
                last_name=CASE WHEN ? THEN excluded.last_name ELSE accounts.last_name END,
                last_seen=excluded.last_seen""", (user, *values, now, now, complete, complete, complete))
            db.execute("""INSERT INTO request_events(created,user_id,source,scope,action,node,status_code,duration_ms)
                VALUES (?,?,?,?,?,?,?,?)""", (now, user, source, scope, action[:70], node[:30], status, round(duration, 2)))
            db.execute('DELETE FROM request_events WHERE created<?', (now - 14 * 86400,))
            db.execute('DELETE FROM request_events WHERE id <= (SELECT MAX(id)-30000 FROM request_events)')

    def audit(self, actor, action, target):
        try:
            with self.vpn.db() as db:
                db.execute('INSERT INTO admin_audit(created,actor,action,target) VALUES (?,?,?,?)', (int(time.time()), actor, action, str(target)[:200]))
            return True
        except sqlite3.Error:
            print('Administrative audit could not be saved.', flush=True)
            return False

    def readiness(self):
        checks = []

        def check(label, ok, required=True):
            checks.append({'label': label, 'ok': bool(ok), 'required': required})
        check('Токен Telegram-бота', settings.TOKEN)
        check('Внутренний ключ API', settings.BOT_KEY)
        check('Список разрешённых пользователей', settings.ALLOW)
        try:
            url = urlsplit(settings.PUBLIC_URL)
        except ValueError:
            url = urlsplit('')
        personal = settings.personal_test_owner() is not None
        check('HTTPS для личного теста' if personal else 'Постоянный адрес HTTPS', url.scheme == 'https' and bool(url.hostname) and (personal or not url.hostname.endswith('.trycloudflare.com')))
        common_ready = all((row['ok'] for row in checks))
        try:
            telegram_ready = proxy.available(proxy.load_nodes())
        except (OSError, ValueError, TypeError):
            telegram_ready = False
        tools = bool(shutil.which(settings.WG_BIN) and shutil.which('ssh'))
        try:
            public_device_ready = any((device_vpn.available(node) for node in device_vpn.load_nodes().values()))
        except (OSError, ValueError, TypeError):
            public_device_ready = False
        check('Утилиты WireGuard и SSH', tools, required=not (telegram_ready or public_device_ready))
        try:
            nodes = wg.load_nodes()
            device_configured = bool(nodes)
        except (OSError, ValueError, TypeError, KeyError):
            device_configured = False
        check('Конфигурация реальных VPN-серверов', device_configured or public_device_ready, required=not telegram_ready)
        check('Прокси Telegram: управляемый или публичный', telegram_ready, required=not (tools and device_configured or public_device_ready))
        device_ready = common_ready and (tools and device_configured or public_device_ready)
        return {'checks': checks, 'device_ready': device_ready, 'live_ready': common_ready and (device_ready or telegram_ready), 'telegram_ready': common_ready and telegram_ready, 'telegram_note': 'MTProto готов: подключение открывается прямо в Telegram.' if telegram_ready else 'Управляемый MTProto-сервер пока недоступен.'}

    def servers(self):
        with self.vpn.db() as db:
            policies = {(r['scope'], r['node']): dict(r) for r in db.execute('SELECT * FROM server_policies')}
            metrics = {(r['scope'], r['node']): dict(r) for r in db.execute('SELECT * FROM server_metrics')}
            counts = {(r['scope'], r['node']): r['count'] for r in db.execute("SELECT scope,node,COUNT(*) AS count FROM profiles WHERE state='active' AND (expires=0 OR expires>?) GROUP BY scope,node", (int(time.time()),))}
        rows = []
        with self.probe_lock:
            pending = set(self.pending)
        for (scope, nodes) in self.vpn.catalogs.items():
            for node in nodes.values():
                metric = metrics.get((scope, node.id), {'state': 'unknown', 'note': 'Метрики ещё не собраны.'})
                public_device = device_vpn.public(node)
                public_telegram = scope == 'telegram' and proxy.public(node)
                external = public_device or public_telegram
                if external and (public_device or node.checked_at > 0) and node.checked_at > metric.get('sampled_at', -1):
                    ready = device_vpn.available(node) if public_device else proxy.available({node.id:node})
                    if public_device:
                        note = 'Туннель OpenVPN и HTTPS через него проверены; задержка HTTPS, не скорость канала.'
                    else:
                        note = 'Получен ответ Telegram через MTProto; это задержка подключения, не скорость канала.'
                    metric = {'state': 'online' if ready else 'unavailable', 'sampled_at': node.checked_at,
                              'latency_ms': node.latency_ms or None, 'download_mbps': None, 'upload_mbps': None,
                              'peer_count': None, 'note':note if ready else 'Нет свежей успешной проверки подключения.'}
                if metric.get('state') == 'online' and int(time.time()) - metric.get('sampled_at', 0) > (7200 if external else 300):
                    metric = {**metric, 'state': 'stale', 'download_mbps': None, 'upload_mbps': None, 'latency_ms': None, 'peer_count': None, 'note': 'Замер устарел. Повторите проверку.'}
                rows.append({'id': node.id, 'scope': scope, 'name': node_display_name(node), 'protocol': 'OpenVPN' if device_vpn.public(node) else SCOPES[scope]['protocol'], 'autodiscovered': device_vpn.public(node), 'endpoint': node.endpoint if device_vpn.public(node) else None, 'maintenance': bool(policies.get((scope, node.id), {}).get('maintenance')), 'note': policies.get((scope, node.id), {}).get('note', ''), 'profiles': counts.get((scope, node.id), 0), 'metric': metric, 'measurable': scope == 'device' or proxy.managed(node) or proxy.probe_supported(node), 'metric_kind': 'availability' if device_vpn.public(node) or (scope == 'telegram' and proxy.public(node)) else 'traffic', 'access_type': 'public' if device_vpn.public(node) or (scope == 'telegram' and proxy.public(node)) else 'managed', 'measuring': (scope, node.id) in pending})
        return rows

    def snapshot(self, actor):
        self.require(actor)
        now = int(time.time())
        with self.vpn.lock, self.vpn.db() as db:
            users = [dict(row) for row in db.execute("""SELECT a.*,
                (SELECT COUNT(*) FROM request_events e WHERE e.user_id=a.user_id AND created>?) AS requests_24h
                FROM accounts a ORDER BY last_seen DESC LIMIT 500""", (now - 86400,))]
            latest = {}
            if users:
                identifiers = [user['user_id'] for user in users]
                placeholders = ','.join(('?' for _ in identifiers))
                for row in db.execute("""SELECT id,user_id,scope,node,state,expires,session_enabled,session_pending FROM profiles
                    WHERE id IN (SELECT MAX(id) FROM profiles GROUP BY user_id,scope)
                    AND user_id IN (""" + placeholders + ')', identifiers):
                    latest[row['user_id'], row['scope']] = row
            for user in users:
                user['profiles'] = {scope: self.vpn.profile_status(latest.get((user['user_id'], scope)), scope) for scope in SCOPES}
                user['is_admin'] = is_admin(user['user_id'])
                user['live_access'] = self.vpn.live_access(user['user_id'], user)
                for scope in SCOPES:
                    user.pop('live_' + scope, None)
            events = [dict(row) for row in db.execute("""SELECT e.*,a.username,a.first_name,a.last_name FROM request_events e
                LEFT JOIN accounts a ON a.user_id=e.user_id ORDER BY e.id DESC LIMIT 300""")]
            audit = [dict(row) for row in db.execute('SELECT * FROM admin_audit ORDER BY id DESC LIMIT 100')]
            request_count = db.execute('SELECT COUNT(*) FROM request_events WHERE created>?', (now - 86400,)).fetchone()[0]
            errors = db.execute('SELECT COUNT(*) FROM request_events WHERE created>? AND status_code>=400', (now - 86400,)).fetchone()[0]
            active = db.execute("SELECT scope,COUNT(*) FROM profiles WHERE state='active' AND (expires=0 OR expires>?) GROUP BY scope", (now,)).fetchall()
            total_users = db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]
            blocked = db.execute('SELECT COUNT(*) FROM accounts WHERE blocked=1').fetchone()[0]
            buckets = {r[0]: r[1] for r in db.execute('SELECT CAST(created/3600 AS INTEGER),COUNT(*) FROM request_events WHERE created>? GROUP BY 1', (now - 86400,))}
        return {'runtime_id': self.runtime_id, 'mode': 'live', 'personal_test': settings.PERSONAL_TEST, 'admin_id': actor, 'updated_at': now, 'readiness': self.readiness(), 'stats': {'users': total_users, 'blocked': blocked, 'requests_24h': request_count, 'errors_24h': errors, 'active': {r[0]: r[1] for r in active}}, 'servers': self.servers(), 'users': users, 'events': events, 'audit': audit, 'activity': [{'hour': h * 3600, 'requests': buckets.get(h, 0)} for h in range(now // 3600 - 23, now // 3600 + 1)], 'limits': {'users': 500, 'events': 300, 'retention_days': 14}, 'speed_note': 'Скорость — текущий трафик WireGuard или управляемого Telegram-прокси между двумя замерами, а не максимальная пропускная способность.'}

    def real_servers(self, actor):
        self.require(actor)
        return self.registry.catalog()

    def edit_real_server(self, actor, body):
        self.require(actor)
        try:
            result = self.registry.change(body)
        except OSError:
            raise Problem(503, 'Не удалось записать настройки серверов. Проверьте доступ к файлу конфигурации.') from None
        self.audit(actor, 'real_server_' + result['action'], result['scope'] + ':' + result['node'])
        return result

    def server_policy(self, actor, body):
        self.require(actor)
        scope = self.vpn.validate_scope(body.get('scope'))
        node = body.get('node')
        if not isinstance(node, str) or node not in self.vpn.catalogs[scope]:
            raise Problem(400, 'Сервер не найден.')
        maintenance = body.get('maintenance')
        note = body.get('note', '')
        if type(maintenance) is not bool or not isinstance(note, str) or len(note) > 200:
            raise Problem(400, 'Проверьте статус обслуживания и заметку (до 200 символов).')
        with self.vpn.lock, self.vpn.db() as db:
            db.execute("""INSERT INTO server_policies(scope,node,maintenance,note) VALUES (?,?,?,?)
                ON CONFLICT(scope,node) DO UPDATE SET maintenance=excluded.maintenance,note=excluded.note""", (scope, node, int(maintenance), note.strip()))
        self.audit(actor, 'server_maintenance' if maintenance else 'server_available', scope + ':' + node)
        return {'ok': True}

    def account_policy(self, actor, body):
        self.require(actor)
        user = body.get('user_id')
        if type(user) is not int or not 0 < user < 2 ** 63:
            raise Problem(400, 'Некорректный аккаунт или статус.')
        if 'live_access' in body:
            scope = self.vpn.validate_scope(body.get('scope'))
            allowed = body['live_access']
            if type(allowed) is not bool or set(body) - {'user_id', 'scope', 'live_access'}:
                raise Problem(400, 'Укажите режим и разрешение доступа.')
            if is_admin(user) and (not allowed):
                raise Problem(409, 'Закрыть доступ администратора нельзя.')
            with self.vpn.lock:
                with self.vpn.db() as db:
                    result = db.execute(f'UPDATE accounts SET live_{scope}=? WHERE user_id=?', (int(allowed), user))
                    if not result.rowcount:
                        raise Problem(404, 'Аккаунт не найден. Сначала откройте бота с этого аккаунта.')
                self.audit(actor, 'live_access_granted' if allowed else 'live_access_denied', f'{user}:{scope}')
                pending = False
                external = False
                if not allowed:
                    row = self.vpn.current(user, scope)
                    if row and row['state'] in ('active', 'creating', 'revoking'):
                        node = self.vpn.catalogs[scope][row['node']]
                        external = device_vpn.public(node) or (scope == 'telegram' and proxy.public(node))
                        try:
                            self.vpn.remove(row)
                        except (wg.WireGuardError, OSError):
                            pending = True
            return {'ok': True, 'pending_revoke': pending, 'external_notice': 'Профиль удалён из бота. Общая конфигурация внешнего оператора остаётся действительной; отключите соединение в приложении-клиенте.' if external else None}
        blocked = body.get('blocked')
        if type(blocked) is not bool or set(body) - {'user_id', 'blocked'}:
            raise Problem(400, 'Некорректный аккаунт или статус.')
        if is_admin(user) and blocked:
            raise Problem(409, 'Блокировка администратора недоступна.')
        with self.vpn.lock, self.vpn.db() as db:
            result = db.execute('UPDATE accounts SET blocked=? WHERE user_id=?', (int(blocked), user))
            if not result.rowcount:
                raise Problem(404, 'Аккаунт не найден.')
        self.audit(actor, 'account_blocked' if blocked else 'account_allowed', user)
        return {'ok': True}

    def revoke(self, actor, body):
        self.require(actor)
        user = body.get('user_id')
        scope = self.vpn.validate_scope(body.get('scope'))
        if type(user) is not int or not 0 < user < 2 ** 63 or type(body.get('expected_profile')) is not int:
            raise Problem(400, 'Укажите аккаунт и актуальный профиль.')
        previous = self.vpn.status(user, scope)
        profile = self.vpn.revoke(user, body['expected_profile'], body.get('expected_status'), scope)
        self.audit(actor, 'profile_revoked', f"{user}:{scope}:{body['expected_profile']}")
        return {'ok': True, 'profile': profile, 'external_notice': ('Профиль убран из бота. Отключите VPN в OpenVPN Connect.' if scope == 'device' else 'Профиль убран из бота. Публичный прокси нужно выключить в настройках Telegram.') if previous.get('access_type') == 'public' else None}

    def restart(self, actor, body):
        self.require(actor)
        if body.get('confirm') is not True:
            raise Problem(400, 'Подтвердите перезапуск.')
        if os.getenv('NORTHLINE_SUPERVISED') != '1':
            raise Problem(409, 'Запустите проект через python3 run.py для управляемого перезапуска.')
        with self.vpn.lock:
            self.vpn.restarting = True
        self.audit(actor, 'service_restart', 'live')
        return {'ok': True, 'mode': 'live', 'restart_required': True, 'previous_runtime_id': self.runtime_id}

    def request_restart(self):
        temporary = None
        try:
            settings.RESTART_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary = settings.RESTART_FILE.with_suffix('.' + secrets.token_hex(6))
            temporary.write_text(secrets.token_hex(12))
            os.replace(temporary, settings.RESTART_FILE)
            return True
        except OSError:
            with self.vpn.lock:
                self.vpn.restarting = False
            print('Restart marker could not be saved; the current service remains available.', flush=True)
            return False
        finally:
            if temporary is not None and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def measure(self, actor, body):
        self.require(actor)
        scope = self.vpn.validate_scope(body.get('scope'))
        node_id = body.get('node')
        with self.vpn.lock:
            node = self.vpn.catalogs[scope].get(node_id) if isinstance(node_id, str) else None
            if node is None:
                raise Problem(400, 'Сервер не найден.')
            external = device_vpn.public(node) or (scope == 'telegram' and proxy.public(node))
            if scope == 'telegram' and (not proxy.managed(node)) and (not proxy.probe_supported(node)):
                raise Problem(409, 'Для этого сервера ещё не подключён способ проверки.')
            key = (scope, node_id)
            with self.probe_lock:
                if key in self.pending:
                    return {'ok': True, 'pending': True}
                if len(self.pending) >= 3:
                    raise Problem(429, 'Одновременно можно проверять до трёх серверов.')
                self.pending.add(key)
            try:
                threading.Thread(target=self._measure_window, args=(scope, node_id, node), daemon=True).start()
            except (OSError, RuntimeError):
                with self.probe_lock:
                    self.pending.discard(key)
                raise Problem(503, 'Не удалось начать замер. Повторите запрос.') from None
            self.audit(actor, 'metrics_requested', scope + ':' + node_id)
            return {'ok': True, 'pending': True, 'duration_seconds': 40 if device_vpn.public(node) else 15 if external else 10, 'kind': 'availability' if external else 'traffic'}

    def _measure_window(self, scope, node_id, node):
        try:
            if device_vpn.public(node):
                self._check_device_vpn(node)
                return
            if scope == 'telegram' and proxy.public(node):
                self._check_public(node)
                return
            if self._probe(scope, node_id, node):
                time.sleep(10)
                if self._probe(scope, node_id, node):
                    with self.vpn.lock, self.vpn.db() as db:
                        db.execute("UPDATE server_metrics SET note=? WHERE scope=? AND node=? AND state='online' AND download_mbps IS NULL", ('Счётчики сервера изменились во время замера. Запустите замер ещё раз.', scope, node_id))
        except (sqlite3.Error, OSError, ValueError):
            print('Server measurement is temporarily unavailable.', flush=True)
        finally:
            with self.probe_lock:
                self.pending.discard((scope, node_id))

    def _check_device_vpn(self, node):
        try:
            result = device_vpn.check(node)
            latency = result['latency_ms']
            state = 'online'
            note = 'Проверен настоящий туннель OpenVPN и HTTPS через него. Задержка HTTPS, не скорость канала.'
        except wg.WireGuardError:
            latency = None
            state = 'unavailable'
            note = 'Туннель OpenVPN или выход в интернет через него недоступен.'
        with self.vpn.lock, self.vpn.db() as db:
            if self.vpn.catalogs['device'].get(node.id) != node:
                return
            db.execute('INSERT OR REPLACE INTO server_metrics VALUES (?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,?,NULL)', ('device', node.id, int(time.time()), state, latency, note))

    def _check_public(self, node):
        try:
            latency = public_proxy.check(node)
            state = 'online'
            note = 'Обмен с Telegram проверен. Счётчики трафика внешнего оператора недоступны.'
        except wg.WireGuardError:
            latency = None
            state = 'unavailable'
            note = 'Не удалось проверить публичный прокси. Проверьте подключение и Docker; попробуйте другую локацию.'
        with self.vpn.lock, self.vpn.db() as db:
            current = self.vpn.catalogs['telegram'].get(node.id)
            if current != node:
                return
            db.execute('INSERT OR REPLACE INTO server_metrics VALUES (?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,?,NULL)', ('telegram', node.id, int(time.time()), state, latency, note))

    def _probe(self, scope, node_id, node=None):
        start = time.monotonic()
        with self.vpn.lock:
            node = node or self.vpn.catalogs[scope].get(node_id)

        def still_current():
            current = self.vpn.catalogs[scope].get(node_id)
            fields = ('id', 'subnet', 'endpoint', 'public_key', 'ssh_host') if scope == 'device' else ('id', 'host', 'port', 'secret')
            return current is not None and all((getattr(current, key) == getattr(node, key) for key in fields))
        try:
            if node is None:
                raise ValueError
            with self.vpn.lock:
                if not still_current():
                    return False
            data = proxy.metrics(node) if scope == 'telegram' else json.loads(wg.control(node, 'metrics'))
            sampled = data['sampled_at'] if scope == 'telegram' else int(time.time())
            sample_id = data['sample_id'] if scope == 'telegram' else None
            values = [data[key] for key in ('rx_bytes', 'tx_bytes', 'peer_count')]
            if any((type(value) is not int or not 0 <= value <= 2 ** 63 - 1 for value in values)):
                raise ValueError
            (rx, tx, peers) = values
            with self.vpn.lock, self.vpn.db() as db:
                if not still_current():
                    return False
                old = db.execute('SELECT * FROM server_metrics WHERE scope=? AND node=?', (scope, node_id)).fetchone()
                interval = sampled - old['sampled_at'] if old else 0
                valid = old and interval > 0 and (old['rx_bytes'] is not None) and (rx >= old['rx_bytes']) and (tx >= old['tx_bytes']) and (scope != 'telegram' or old['sample_id'] == sample_id)
                down = round((tx - old['tx_bytes']) * 8 / interval / 1000000.0, 3) if valid else None
                up = round((rx - old['rx_bytes']) * 8 / interval / 1000000.0, 3) if valid else None
                db.execute('INSERT OR REPLACE INTO server_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (scope, node_id, sampled, 'online', None if scope == 'telegram' else round((time.monotonic() - start) * 1000, 1), rx, tx, down, up, peers, '' if valid else 'Первый отсчёт готов. Ждём завершения замера.', sample_id))
            return True
        except (wg.WireGuardError, ValueError, KeyError, TypeError, OSError):
            with self.vpn.lock, self.vpn.db() as db:
                if not still_current():
                    return False
                note = 'Метрики Telegram-прокси недоступны. Проверьте контейнер и сбор счётчиков; само соединение прокси может продолжать работать.' if scope == 'telegram' else 'Сервер не ответил. Проверьте SSH и обновите deploy/node_control.py на узле.'
                db.execute('INSERT OR REPLACE INTO server_metrics VALUES (?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,?,NULL)', (scope, node_id, int(time.time()), 'unavailable', note))
            return False
