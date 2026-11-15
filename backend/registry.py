"""Versioned server configuration."""
import hashlib
import json
import os
import secrets
import sqlite3
import time
import settings
from backend import wireguard as wg, proxy, device_vpn
from backend.service import Problem
from backend.geolocation import detect_location
from backend.catalog import country_flag, location_details

class Registry:

    def __init__(self, vpn):
        self.vpn = vpn

    def path(self, scope):
        self.vpn.validate_scope(scope)
        return settings.NODES if scope == 'device' else settings.PROXY_NODES

    def read(self, scope):
        path = self.path(scope)
        try:
            raw = path.read_bytes() if path.exists() else b''
        except OSError:
            raise Problem(503, 'Не удалось прочитать настройки серверов.') from None
        revision = hashlib.sha256(raw).hexdigest()
        try:
            rows = json.loads(raw) if raw else []
            self.validate(scope, rows)
        except (ValueError, TypeError, KeyError) as error:
            raise Problem(409, 'Не удалось прочитать список серверов: ' + str(error)) from None
        return (rows, revision, raw)

    def validate(self, scope, rows):
        if scope == 'device':
            return wg.parse_nodes(rows, allow_empty=True)
        return proxy.parse_nodes(rows)

    def live_profiles(self, scope, node):
        path = settings.DB
        if not path.exists():
            return 0
        try:
            with sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True) as db:
                if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='profiles'").fetchone():
                    return 0
                columns = {row[1] for row in db.execute('PRAGMA table_info(profiles)')}
                if 'scope' not in columns:
                    if scope != 'device':
                        return 0
                    return db.execute("SELECT COUNT(*) FROM profiles WHERE node=? AND state IN ('active','creating','revoking')", (node,)).fetchone()[0]
                return db.execute("SELECT COUNT(*) FROM profiles WHERE scope=? AND node=? AND state IN ('active','creating','revoking')", (scope, node)).fetchone()[0]
        except (sqlite3.Error, OSError):
            raise Problem(409, 'Не удалось проверить действующие профили. Изменения не сохранены.') from None

    def catalog(self):
        catalogs = {}
        for scope in ('device', 'telegram'):
            try:
                (rows, revision, _) = self.read(scope)
                catalogs[scope] = {'revision': revision, 'rows': [{**{k: v for (k, v) in row.items() if k != 'secret'}, 'has_secret': bool(row.get('secret')), 'enabled': row.get('enabled', True), 'profiles': self.live_profiles(scope, row['id'])} for row in rows], 'error': None}
            except (Problem, OSError) as error:
                catalogs[scope] = {'revision': None, 'rows': [], 'error': error.message if isinstance(error, Problem) else 'Не удалось прочитать файл конфигурации.'}
        return {'catalogs': catalogs, 'active_mode': 'live', 'note': 'Здесь только добавленные реальные серверы. Наличие в списке не означает доступность по сети.'}

    def change(self, body):
        if body.get('action') != 'save':
            return self._change(body)
        scope = self.vpn.validate_scope(body.get('scope'))
        with self.vpn.lock:
            if getattr(self.vpn, 'restarting', False):
                raise Problem(409, 'Идёт перезапуск. Повторите действие позже.')
            (rows, revision, _) = self.read(scope)
            if body.get('expected_revision') != revision:
                raise Problem(409, 'Список серверов уже изменился. Обновите его и откройте форму заново.')
            original = body.get('original_id')
            old = next((row for row in rows if row['id'] == original), None)
            if original is not None and old is None:
                raise Problem(404, 'Редактируемый сервер уже удалён.')
            source = body.get('server')
            if not isinstance(source, dict) or not isinstance(source.get('name'), str):
                raise Problem(400, 'Заполните параметры сервера.')
            node = {key: value for (key, value) in source.items() if key not in ('country', 'country_name')}
            if scope == 'telegram' and old and (not node.get('secret')) and old.get('secret'):
                node['secret'] = old['secret']
            if scope == 'telegram' and old:
                # The browser editor changes connection fields, not scan metadata.
                for key in ('checked_at', 'latency_ms', 'retired'):
                    if key in old:
                        node[key] = old[key]
                if any(node.get(key) != old.get(key) for key in ('host', 'port', 'secret')):
                    if 'checked_at' in node:
                        node['checked_at'] = 0
                    if 'latency_ms' in node:
                        node['latency_ms'] = 0
            node['name'] = node['name'].strip()
            candidate = {**node, 'name': node['name'] or node.get('id', '')}
            proposed = [candidate if row['id'] == original else row for row in rows] if old else rows + [candidate]
            try:
                self.validate(scope, proposed)
            except (ValueError, TypeError, KeyError) as error:
                raise Problem(400, str(error)) from None
            if old and node.get('id') != original:
                raise Problem(400, 'ID существующего сервера менять нельзя.')
            host = lambda row: row['host'] if scope == 'telegram' else row['endpoint'].rsplit(':', 1)[0]
            changed = not old or host(old) != host(node)
            old_country = {key: old[key] for key in ('country', 'country_name') if key in old} if old else {}
            lookup = changed or len(old_country) != 2
        location = detect_location(host(node)) if lookup else old_country
        warning = None
        if location:
            node.update(location)
            auto_name = country_flag(location['country']) + ' ' + location['country_name']
            if not node['name'] or (old and node['name'] == old['name'] and location_details(old['name'])['flag']):
                node['name'] = auto_name
        else:
            warning = 'Сервер сохранён, но страну определить не удалось. Проверьте публичный адрес и повторите сохранение.'
            if changed and old and (node['name'] == old['name']) and location_details(old['name'])['flag']:
                node['name'] = ''
            node['name'] = node['name'] or 'Сервер ' + node['id']
        result = self._change({**body, 'server': node})
        result['location_warning'] = warning
        result['location'] = country_flag(location['country']) + ' ' + location['country_name'] if location else None
        return result

    def _change(self, body):
        scope = self.vpn.validate_scope(body.get('scope'))
        action = body.get('action')
        if action not in ('save', 'delete'):
            raise Problem(400, 'Выберите сохранение или удаление сервера.')
        with self.vpn.lock:
            if getattr(self.vpn, 'restarting', False):
                raise Problem(409, 'Идёт перезапуск. Повторите действие позже.')
            (rows, revision, raw) = self.read(scope)
            if body.get('expected_revision') != revision:
                raise Problem(409, 'Список серверов уже изменился. Обновите его и откройте форму заново.')
            original = body.get('original_id')
            old = next((row for row in rows if row['id'] == original), None)
            if original is not None and (not old):
                raise Problem(404, 'Редактируемый сервер уже удалён.')
            if action == 'delete':
                if not old or body.get('confirm') is not True:
                    raise Problem(400, 'Подтвердите удаление сервера.')
                proposed = [row for row in rows if row['id'] != original]
            else:
                node = body.get('server')
                if not isinstance(node, dict):
                    raise Problem(400, 'Заполните параметры сервера.')
                if old and node.get('id') != original:
                    raise Problem(400, 'ID существующего сервера менять нельзя.')
                if not old and any((row['id'] == node.get('id') for row in rows)):
                    raise Problem(409, 'Такой ID уже используется.')
                proposed = [node if row['id'] == original else row for row in rows] if old else rows + [node]
            try:
                nodes = self.validate(scope, proposed)
            except (ValueError, TypeError, KeyError) as error:
                raise Problem(400, str(error)) from None
            if scope == 'device' and (not nodes) and (not any((device_vpn.public(value) and device_vpn.available(value) for value in self.vpn.catalogs['device'].values()))):
                raise Problem(409, 'Нельзя отключить последний VPN-сервер в работающем реальном режиме.')
            structural = True
            if old:
                structural = action == 'delete' or any((old.get(key, True if key == 'enabled' else None) != body.get('server', {}).get(key, True if key == 'enabled' else None) for key in set(old) | {'enabled'} if key not in ('name', 'country', 'country_name')))
                if structural and self.live_profiles(scope, old['id']):
                    raise Problem(409, 'На сервере есть действующие профили. Можно изменить название; для других изменений сначала отзовите доступ.')
            node_id = original or body['server']['id']
            with self.vpn.db() as db:
                if structural and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_metrics'").fetchone():
                    db.execute('DELETE FROM server_metrics WHERE scope=? AND node=?', (scope, node_id))
            path = self.path(scope)
            path.parent.mkdir(parents=True, exist_ok=True)
            if raw:
                backups = path.parent / 'registry-backups'
                backups.mkdir(mode=448, exist_ok=True)
                backup = backups / (path.stem + '-' + str(time.time_ns()) + '-' + secrets.token_hex(3) + '.json')
                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
            temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
            try:
                fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(proposed, stream, ensure_ascii=False, indent=2)
                    stream.write('\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if temporary.exists():
                    temporary.unlink()
            self.vpn.catalogs[scope] = {**nodes, **{key: value for (key, value) in self.vpn.catalogs[scope].items() if device_vpn.public(value)}} if scope == 'device' else nodes
            if scope == 'device':
                self.vpn.nodes = nodes
            return {'ok': True, 'scope': scope, 'node': node_id, 'applied': 'live' == 'live', 'action': action}
