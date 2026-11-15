import sqlite3
import threading
import time
import base64
import hashlib
import hmac
import json
import secrets
from contextlib import contextmanager
import settings
from backend import wireguard as wg
from backend import proxy
from backend import device_vpn
from backend.clients import client_for
from backend.catalog import SCOPES, PLATFORMS, TELEGRAM_PRIORITY, instructions, location_details, node_display_name

def ensure_profile_sequence(db):
    """Keep profile IDs increasing even after an explicit history cleanup."""
    db.execute('CREATE TABLE IF NOT EXISTS profile_sequence (singleton INTEGER PRIMARY KEY CHECK(singleton=1), next_id INTEGER NOT NULL)')
    db.execute('INSERT OR IGNORE INTO profile_sequence SELECT 1,COALESCE(MAX(id),0)+1 FROM profiles')
    db.execute('UPDATE profile_sequence SET next_id=MAX(next_id,COALESCE((SELECT MAX(id)+1 FROM profiles),1)) WHERE singleton=1')

class Problem(Exception):

    def __init__(self, status, message):
        (self.status, self.message) = (status, message)

class VPN:

    def __init__(self):
        self.nodes = wg.load_nodes()
        public_device_nodes = device_vpn.load_nodes()
        self.catalogs = {'device': {**self.nodes, **public_device_nodes} if public_device_nodes else self.nodes, 'telegram': proxy.load_nodes()}
        self.lock = threading.RLock()
        self.import_key = secrets.token_bytes(32)
        settings.DB.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'device',
                    node TEXT NOT NULL,
                    address TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    state TEXT NOT NULL,
                    expires INTEGER NOT NULL
                );
                PRAGMA secure_delete = ON;
                CREATE TABLE IF NOT EXISTS accounts (
                    user_id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '',
                    first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '',
                    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, blocked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS server_policies (
                    scope TEXT NOT NULL, node TEXT NOT NULL, maintenance INTEGER NOT NULL DEFAULT 0,
                    note TEXT NOT NULL DEFAULT '', PRIMARY KEY(scope,node)
                );
            """)
            columns = {row['name'] for row in db.execute('PRAGMA table_info(profiles)')}
            if 'scope' not in columns:
                db.execute("ALTER TABLE profiles ADD COLUMN scope TEXT NOT NULL DEFAULT 'device'")
            for (column, default) in (('session_enabled', 1), ('session_pending', 0)):
                if column not in columns:
                    db.execute(f'ALTER TABLE profiles ADD COLUMN {column} INTEGER NOT NULL DEFAULT {default} CHECK ({column} IN (0,1))')
            account_columns = {row['name'] for row in db.execute('PRAGMA table_info(accounts)')}
            for scope in SCOPES:
                column = 'live_' + scope
                if column not in account_columns:
                    db.execute(f'ALTER TABLE accounts ADD COLUMN {column} INTEGER CHECK ({column} IN (0,1))')
            db.executescript("""
                CREATE INDEX IF NOT EXISTS profile_history ON profiles(user_id,scope,id DESC);
                DROP INDEX IF EXISTS current_user;
                DROP INDEX IF EXISTS current_address;
                CREATE UNIQUE INDEX IF NOT EXISTS current_user_scope ON profiles(user_id,scope)
                    WHERE state IN ('creating','active','revoking');
                CREATE UNIQUE INDEX IF NOT EXISTS current_address_device ON profiles(node,address)
                    WHERE scope='device' AND state IN ('creating','active','revoking');
            """)
            ensure_profile_sequence(db)
            for (scope, node) in db.execute("SELECT DISTINCT scope,node FROM profiles WHERE state IN ('creating','active','revoking')"):
                if node not in self.catalogs.get(scope, {}):
                    raise ValueError('Restore removed nodes with outstanding profiles before starting.')
            db.execute('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)')
            if not db.execute("SELECT 1 FROM schema_migrations WHERE name='permanent-access-v1'").fetchone():
                rows = list(db.execute("SELECT id,scope,node FROM profiles WHERE state IN ('active','creating')"))
                for row in rows:
                    node = self.catalogs[row['scope']][row['node']]
                    provision = row['scope'] == 'device' and (not device_vpn.public(node)) or (row['scope'] == 'telegram' and proxy.managed(node))
                    db.execute("UPDATE profiles SET expires=0,state=CASE WHEN ? THEN 'creating' ELSE state END WHERE id=?", (provision, row['id']))
                db.execute("INSERT INTO schema_migrations VALUES ('permanent-access-v1')")

    def validate_scope(self, scope):
        if not isinstance(scope, str) or scope not in SCOPES:
            raise Problem(400, 'Выберите режим: всё устройство или только Telegram.')
        return scope

    def available(self, scope):
        self.validate_scope(scope)
        if scope == 'device':
            return bool(self.nodes) or any((device_vpn.available(node) for node in self.catalogs['device'].values() if device_vpn.public(node)))
        return proxy.available(self.catalogs['telegram'])

    def live_access(self, user, account=None):
        if account is None:
            with self.db() as db:
                account = db.execute('SELECT * FROM accounts WHERE user_id=?', (user,)).fetchone()
        default = settings.ALLOW == '*' or str(user) in {item.strip() for item in settings.ALLOW.split(',')}
        result = {}
        for scope in SCOPES:
            override = account['live_' + scope] if account is not None else None
            result[scope] = {'allowed': bool(default if override is None else override), 'source': 'environment' if override is None else 'account'}
        return result

    def visible_nodes(self, scope, user=None):
        self.validate_scope(scope)
        if user is not None and (not self.live_access(user)[scope]['allowed']):
            return []
        with self.db() as db:
            policies = {row['node']: bool(row['maintenance']) for row in db.execute('SELECT node,maintenance FROM server_policies WHERE scope=?', (scope,))}
        nodes = list(self.catalogs[scope].values())
        if scope == 'telegram':
            nodes.sort(key=lambda node: TELEGRAM_PRIORITY.index(node.country) if node.country in TELEGRAM_PRIORITY else len(TELEGRAM_PRIORITY))
        else:
            nodes.sort(key=lambda node: node.country not in device_vpn.REQUIRED_COUNTRIES)
        return [{'id': node.id, 'name': node_display_name(node), 'server_name': node.name, **location_details(node.name, node.country, node.country_name), 'maintenance': policies.get(node.id, False) or (device_vpn.public(node) and (not device_vpn.available(node))), 'protocol': 'OpenVPN' if device_vpn.public(node) else SCOPES[scope]['protocol'], 'access_type': 'public' if device_vpn.public(node) or (scope == 'telegram' and proxy.public(node)) else 'managed'} for node in nodes if not getattr(node, 'retired', False)]

    @contextmanager
    def db(self):
        connection = sqlite3.connect(settings.DB)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                connection.execute('PRAGMA secure_delete = ON')
                yield connection
        finally:
            connection.close()

    def current(self, user, scope='device'):
        self.validate_scope(scope)
        with self.db() as db:
            return db.execute('SELECT * FROM profiles WHERE user_id=? AND scope=? ORDER BY id DESC LIMIT 1', (user, scope)).fetchone()

    def status(self, user, scope='device'):
        with self.lock:
            return self.profile_status(self.current(user, scope), scope)

    def profile_status(self, row, scope):
        if row is None:
            return {'status': 'none', 'scope': scope}
        status = row['state']
        node = self.catalogs[scope].get(row['node'])
        if status in ('active', 'creating') and row['expires'] != 0 and (row['expires'] <= time.time()):
            status = 'expired'
        retired = bool(getattr(node, 'retired', False))
        replacement = next((item for item in self.catalogs[scope].values() if not getattr(item, 'retired', False) and node is not None and node.country and (item.country == node.country)), None) if retired else None
        return {'status': status, 'scope': scope, 'id': row['id'], 'node': row['node'], 'server': node_display_name(self.catalogs[scope][row['node']]) if row['node'] in self.catalogs[scope] else row['node'], 'expires': row['expires'], 'unlimited': row['expires'] == 0, 'config_available': status == 'active' and (not retired) and (scope == 'device'), 'connection_available': status == 'active' and (not retired), 'node_retired': retired, 'replacement': {'node': replacement.id, 'server': node_display_name(replacement)} if replacement else None, 'protocol': 'OpenVPN' if device_vpn.public(node) else SCOPES[scope]['protocol'], 'access_type': 'public' if device_vpn.public(node) or (scope == 'telegram' and node and proxy.public(node)) else 'managed', 'session': {'controllable': scope == 'telegram' and node is not None and proxy.managed(node), 'enabled': bool(row['session_enabled']), 'pending': bool(row['session_pending'])}}

    def statuses(self, user):
        with self.lock:
            return {scope: self.status(user, scope) for scope in SCOPES}

    def check_version(self, row, expected, expected_status=None):
        if expected is not None and (type(expected) is not int or expected < 0):
            raise Problem(400, 'Некорректный номер профиля.')
        if expected is not None and expected != (row['id'] if row else 0):
            raise Problem(409, 'Профиль уже изменился. Обновите состояние и повторите действие.')
        if expected_status is not None:
            if expected_status not in ('none', 'active', 'creating', 'revoking', 'revoked', 'expired'):
                raise Problem(400, 'Некорректное состояние профиля.')
            actual = row['state'] if row else 'none'
            if row and actual in ('active', 'creating') and (row['expires'] != 0) and (row['expires'] <= time.time()):
                actual = 'expired'
            if actual != expected_status:
                raise Problem(409, 'Состояние профиля изменилось. Обновите его и подтвердите действие заново.')

    def issue(self, user, node_id, expected=None, expected_status=None, scope='device'):
        self.validate_scope(scope)
        if not self.available(scope):
            raise Problem(503, 'Серверы выбранного режима сейчас недоступны. Обновите состояние или выберите другой режим.')
        with self.lock:
            if not self.live_access(user)[scope]['allowed']:
                raise Problem(403, 'Администратор ещё не разрешил вашему аккаунту режим «' + SCOPES[scope]['name'] + '».')
            node = self.catalogs[scope].get(node_id) if isinstance(node_id, str) else None
            if not node:
                raise Problem(400, 'Этот сервер недоступен. Выберите другой.')
            if getattr(node, 'retired', False):
                raise Problem(409, 'Этот сервер заменён. Обновите список и выберите актуальный сервер.')
            if device_vpn.public(node) and (not device_vpn.available(node)):
                raise Problem(503, 'Этот VPN ещё не прошёл свежую проверку туннеля. Выберите другой сервер.')
            if scope == 'telegram' and (not proxy.managed(node)) and (not proxy.public(node)):
                raise Problem(503, 'Для этого MTProto-сервера ещё не подключено управление доступом.')
            if scope == 'telegram' and (not proxy.available({node.id: node})):
                raise Problem(503, 'Этот прокси сейчас недоступен. Выберите другую локацию.')
            if getattr(self, 'restarting', False):
                raise Problem(503, 'Приложение перезапускается. Повторите запрос через несколько секунд.')
            row = self.current(user, scope)
            self.check_version(row, expected, expected_status)
            with self.db() as db:
                account = db.execute('SELECT blocked FROM accounts WHERE user_id=?', (user,)).fetchone()
                policy = db.execute('SELECT maintenance FROM server_policies WHERE scope=? AND node=?', (scope, node_id)).fetchone()
            same_active = row and row['node'] == node_id and (row['state'] == 'active') and (row['expires'] == 0 or row['expires'] > time.time())
            if not same_active and account and account['blocked']:
                raise Problem(403, 'Создание новых профилей для аккаунта приостановлено администратором.')
            if not same_active and policy and policy['maintenance']:
                raise Problem(409, 'Этот сервер на обслуживании. Выберите другой.')
            expires = 0
            remove_current = False
            if row and row['state'] in ('active', 'creating', 'revoking'):
                if row['state'] == 'revoking' or (row['expires'] != 0 and row['expires'] <= time.time()):
                    remove_current = True
                elif row['node'] != node_id:
                    remove_current = True
                else:
                    if row['state'] == 'creating':
                        self.activate(row)
                    return self.status(user, scope)
            (private, public) = ('', '')
            if scope == 'device' and device_vpn.public(node):
                private = node.config
            elif scope == 'device':
                (private, public) = wg.keys()
            elif not proxy.public(node):
                private = proxy.new_secret()
            if scope == 'telegram' and proxy.managed(node):
                with self.db() as db:
                    count = db.execute("SELECT COUNT(*) FROM profiles WHERE scope='telegram' AND node=? AND state IN ('active','creating') AND (expires=0 OR expires>?)", (node_id, int(time.time()))).fetchone()[0]
                frees_slot = remove_current and row['node'] == node_id and (row['state'] in ('active', 'creating')) and (row['expires'] == 0 or row['expires'] > time.time())
                if count >= 16 and (not frees_slot):
                    raise Problem(409, 'На этом прокси пока нет свободных мест.')
            address = ''
            if scope == 'device' and device_vpn.public(node):
                address = 'public-' + str(user)
            elif scope == 'device':
                with self.db() as db:
                    used = {r[0] for r in db.execute("SELECT address FROM profiles WHERE node=? AND scope='device' AND state IN ('creating','active','revoking')", (node_id,))}
                    if remove_current and row['node'] == node_id:
                        used.discard(row['address'])
                    address = next((str(ip) for ip in list(node.subnet.hosts())[1:] if str(ip) not in used), None)
                    if not address:
                        raise Problem(409, 'На этом сервере нет свободных мест. Выберите другой.')
            if remove_current:
                self.remove(row)
            with self.db() as db:
                db.execute('UPDATE profile_sequence SET next_id=MAX(next_id,COALESCE((SELECT MAX(id)+1 FROM profiles),1))+1 WHERE singleton=1')
                profile_id = db.execute('SELECT next_id-1 FROM profile_sequence WHERE singleton=1').fetchone()[0]
                db.execute("INSERT INTO profiles (id,user_id,scope,node,address,private_key,public_key,state,expires) VALUES (?,?,?,?,?,?,?,'creating',?)", (profile_id, user, scope, node_id, address, private, public, expires))
            self.activate(self.current(user, scope))
            return self.status(user, scope)

    def activate(self, row):
        if row['scope'] == 'device' and (not device_vpn.public(self.catalogs['device'][row['node']])):
            wg.control(self.nodes[row['node']], 'add', row['public_key'], row['address'] + '/32', str(row['expires']))
        if row['scope'] == 'telegram' and proxy.managed(self.catalogs['telegram'][row['node']]):
            proxy.sync(self)
        with self.db() as db:
            db.execute("UPDATE profiles SET state='active' WHERE id=?", (row['id'],))

    def remove(self, row):
        final = 'expired' if row['expires'] != 0 and row['expires'] <= time.time() else 'revoked'
        with self.db() as db:
            db.execute("UPDATE profiles SET state='revoking', private_key='' WHERE id=?", (row['id'],))
        if row['scope'] == 'device' and (not device_vpn.public(self.catalogs['device'][row['node']])):
            wg.control(self.nodes[row['node']], 'remove', row['public_key'])
        if row['scope'] == 'telegram' and proxy.managed(self.catalogs['telegram'][row['node']]):
            proxy.sync(self)
        with self.db() as db:
            db.execute('UPDATE profiles SET state=? WHERE id=?', (final, row['id']))

    def revoke(self, user, expected=None, expected_status=None, scope='device'):
        with self.lock:
            row = self.current(user, scope)
            self.check_version(row, expected, expected_status)
            if row and row['state'] in ('creating', 'active', 'revoking'):
                self.remove(row)
            return self.status(user, scope)

    def config(self, user, scope='device'):
        self.validate_scope(scope)
        with self.lock:
            row = self.current(user, scope)
            if scope != 'device' or not row or row['state'] != 'active' or (row['expires'] != 0 and row['expires'] <= time.time()):
                raise Problem(404, 'Конфигурация недоступна. Нужен активный профиль в рабочем режиме.')
            if getattr(self.catalogs['device'][row['node']], 'retired', False):
                raise Problem(409, 'Этот сервер больше не доступен для подключения. Выберите замену и импортируйте новый конфиг.')
            if device_vpn.public(self.catalogs['device'][row['node']]):
                return row['private_key']
            return wg.client_config(self.nodes[row['node']], row['private_key'], row['address'])

    def session(self, user, enabled, expected, expected_enabled, scope='telegram'):
        """Pause access at our MTProto server, preserving the profile and its secret."""
        self.validate_scope(scope)
        if type(enabled) is not bool or type(expected_enabled) is not bool or type(expected) is not int or (expected <= 0):
            raise Problem(400, 'Обновите профиль перед переключением подключения.')
        with self.lock:
            row = self.current(user, scope)
            self.check_version(row, expected, 'active')
            if scope != 'telegram' or not row or (not proxy.managed(self.catalogs[scope][row['node']])):
                raise Problem(409, 'Этот прокси отключается в настройках Telegram. Профиль удалять не нужно.')
            if bool(row['session_enabled']) != expected_enabled:
                raise Problem(409, 'Подключение уже изменилось. Обновите состояние.')
            if enabled and (not self.live_access(user)[scope]['allowed']):
                raise Problem(403, 'Доступ к этому режиму закрыт администратором.')
            with self.db() as db:
                db.execute('UPDATE profiles SET session_enabled=?,session_pending=1 WHERE id=?', (int(enabled), row['id']))
            proxy.sync(self)
            with self.db() as db:
                db.execute('UPDATE profiles SET session_pending=0 WHERE id=?', (row['id'],))
            return self.status(user, scope)

    def import_link(self, user, profile):
        expires = min(int(time.time()) + 300, profile['expires']) if profile['expires'] else int(time.time()) + 300
        payload = base64.urlsafe_b64encode(json.dumps([user, profile['id'], expires], separators=(',', ':')).encode()).decode().rstrip('=')
        signature = hmac.new(self.import_key, payload.encode(), hashlib.sha256).hexdigest()
        return '/connect-config/' + payload + '.' + signature

    def import_file(self, token):
        """A five-minute capability for one current device profile; no Telegram credentials."""
        try:
            if not isinstance(token, str) or len(token) > 256:
                raise ValueError
            (payload, signature) = token.split('.')
            if not hmac.compare_digest(signature, hmac.new(self.import_key, payload.encode(), hashlib.sha256).hexdigest()):
                raise ValueError
            (user, profile_id, expires) = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
            if any((type(value) is not int for value in (user, profile_id, expires))) or not time.time() < expires <= time.time() + 301:
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise Problem(404, 'Ссылка импорта истекла. Откройте настройку подключения заново.') from None
        with self.lock:
            row = self.current(user, 'device')
            with self.db() as db:
                account = db.execute('SELECT blocked FROM accounts WHERE user_id=?', (user,)).fetchone()
            if not row or row['id'] != profile_id or (not self.live_access(user)['device']['allowed']) or (account and account['blocked']):
                raise Problem(404, 'Конфигурация больше недоступна.')
            content = self.config(user, 'device')
            return ('northline-vpn.ovpn' if device_vpn.public(self.catalogs['device'][row['node']]) else 'northline-vpn.conf', content)

    def connection(self, user, scope='device', platform='other', expected=None, expected_status=None):
        with self.lock:
            self.check_version(self.current(user, scope), expected, expected_status)
            return self._connection(user, scope, platform)

    def _connection(self, user, scope, platform):
        self.validate_scope(scope)
        if not isinstance(platform, str) or platform not in PLATFORMS:
            raise Problem(400, 'Выберите устройство из списка.')
        profile = self.status(user, scope)
        if profile['status'] != 'active':
            raise Problem(409, 'Сначала создайте активный профиль в выбранном режиме.')
        if profile.get('node_retired'):
            raise Problem(409, 'Сервер недоступен или заменён. Откройте профиль, выберите новый сервер и обновите подключение.')
        result = {'scope': scope, 'platform': platform, 'profile': profile, 'protocol': SCOPES[scope]['protocol'], 'steps': instructions(scope, platform), 'connect_url': None, 'download': None}
        if scope == 'device':
            result['download'] = {'filename': 'northline-vpn.conf', 'content': self.config(user, scope)}
            node = self.catalogs['device'][profile['node']]
            if device_vpn.public(node):
                result['protocol'] = 'OpenVPN'
                result['steps'] = device_vpn.instructions(platform)
                result['download']['filename'] = 'northline-vpn.ovpn'
                result['notice'] = device_vpn.NOTICE
            result['client'] = client_for(result['protocol'], platform)
            result['download_url'] = self.import_link(user, profile)
            if result['client'].get('external_import'):
                result['import_page_url'] = result['download_url'].replace('/connect-config/', '/connect-import/', 1)
            result['download_expires'] = min(int(time.time()) + 300, profile['expires']) if profile['expires'] else int(time.time()) + 300
        if scope == 'telegram':
            row = self.current(user, scope)
            node = self.catalogs[scope][row['node']]
            if proxy.managed(node) and (not row['session_enabled'] or row['session_pending']):
                raise Problem(409, 'Доступ на сервере приостановлен или ещё переключается. Включите его кнопкой питания.')
            if not proxy.available({node.id: node}):
                raise Problem(503, 'Прокси Telegram временно недоступен.')
            result['connect_url'] = proxy.connect_url(node, row['private_key'])
            if proxy.public(node):
                result['notice'] = 'Публичный прокси внешнего оператора с общим ключом. Удаление профиля в боте не отключает уже добавленный прокси в Telegram; выключите его в настройках Telegram.'
        return result

    def reconcile_once(self):
        with self.db() as db:
            ids = [(r[0], r[1]) for r in db.execute("SELECT user_id,scope FROM profiles WHERE state IN ('creating','active','revoking')")]
        for (user, scope) in ids:
            with self.lock:
                row = self.current(user, scope)
                if row is None:
                    continue
                try:
                    if row['state'] == 'revoking' or (row['state'] in ('creating', 'active') and row['expires'] != 0 and (row['expires'] <= time.time())):
                        self.remove(row)
                    elif row['state'] == 'creating':
                        self.activate(row)
                    elif row['scope'] == 'telegram' and row['session_pending'] and proxy.managed(self.catalogs['telegram'][row['node']]):
                        proxy.sync(self)
                        with self.db() as db:
                            db.execute('UPDATE profiles SET session_pending=0 WHERE id=?', (row['id'],))
                except wg.WireGuardError:
                    print(f"WireGuard sync failed on node {row['node']}; retrying.", flush=True)

    def reconcile(self):
        while True:
            try:
                self.reconcile_once()
            except (sqlite3.Error, OSError, ValueError):
                print('Profile reconciliation is temporarily unavailable; retrying.', flush=True)
            time.sleep(15)
