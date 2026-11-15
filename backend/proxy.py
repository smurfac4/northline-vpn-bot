"""MTProto catalog and individually revocable access for the managed local node."""
from dataclasses import dataclass, field
import base64
import json
import re
import hashlib
import math
import os
import secrets
import time
from urllib.parse import urlencode
import settings
from backend.catalog import valid_host, country_metadata
from backend.wireguard import WireGuardError

@dataclass(frozen=True)
class ProxyNode:
    id: str
    name: str
    host: str = ''
    port: int = 8443
    country: str = ''
    country_name: str = ''
    secret: str = field(default='', repr=False)
    retired: bool = False
    checked_at: int = 0
    latency_ms: float = 0

def managed(node):
    return bool(settings.MTPROXY_NODE_ID) and node.id == settings.MTPROXY_NODE_ID

def public(node):
    return bool(node.secret) and (not managed(node))

def normalize_secret(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError('Проверьте секрет MTProto.')
    try:
        raw = bytes.fromhex(value) if re.fullmatch('[0-9a-fA-F]+', value) and len(value) % 2 == 0 else base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        if len(raw) == 16 or (len(raw) == 17 and raw[0] == 221):
            return raw.hex()
        if len(raw) > 17 and raw[0] == 238 and valid_host(raw[17:].decode('ascii')):
            return raw.hex()
    except (ValueError, UnicodeError):
        pass
    raise ValueError('Нужен корректный секрет MTProto из ссылки подключения.')

def probe_supported(node):
    return public(node) and (len(node.secret) == 32 or (len(node.secret) == 34 and node.secret.startswith('dd')) or (len(node.secret) > 34 and node.secret.startswith('ee')))

def service_status():
    try:
        result = json.loads((settings.MTPROXY_STATE_DIR / 'status.json').read_text())
        return result if isinstance(result, dict) and result.get('version') == 1 and (result.get('running') is True) and (0 <= time.time() - result['updated'] < 10) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None

def available(nodes):
    if any((public(node) and (not node.retired) and (node.checked_at == 0 or 0 <= time.time() - node.checked_at <= 7200) for node in nodes.values())):
        return True
    status = service_status()
    return bool(status) and any((managed(node) and node.host == status.get('host') and (node.port == status.get('port')) for node in nodes.values()))

def new_secret():
    return secrets.token_hex(16)

def metrics(node):
    status = service_status()
    if not managed(node) or not status or node.host != status.get('host') or (node.port != status.get('port')):
        raise WireGuardError('Managed proxy is unavailable')
    data = status.get('metrics')
    if not isinstance(data, dict):
        raise WireGuardError('Proxy counters are unavailable')
    if type(data.get('sampled_at')) is not int or not 0 <= time.time() - data['sampled_at'] < 10:
        raise WireGuardError('Proxy counters are stale')
    if not isinstance(data.get('sample_id'), str) or not re.fullmatch('[0-9a-f]{16}', data['sample_id']):
        raise WireGuardError('Invalid proxy counter generation')
    fields = ('rx_bytes', 'tx_bytes', 'peer_count')
    if any((type(data.get(key)) is not int or not 0 <= data[key] <= 2 ** 63 - 1 for key in fields)):
        raise WireGuardError('Invalid proxy counters')
    return {key: data[key] for key in (*fields, 'sampled_at', 'sample_id')}

def sync(vpn, timeout=6):
    node_id = settings.MTPROXY_NODE_ID
    if not node_id or node_id not in vpn.catalogs['telegram']:
        raise WireGuardError('Managed Telegram proxy is not configured')
    with vpn.db() as db:
        rows = [{'secret': row['private_key'], 'expires': row['expires']} for row in db.execute("SELECT private_key,expires FROM profiles WHERE scope='telegram' AND node=? AND state IN ('creating','active') AND session_enabled=1 AND (expires=0 OR expires>?) ORDER BY id", (node_id, int(time.time())))]
    if len(rows) > 16 or any((not re.fullmatch('[0-9a-f]{32}', row['secret']) for row in rows)):
        raise WireGuardError('Invalid Telegram proxy access state')
    revision = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    directory = settings.MTPROXY_STATE_DIR
    directory.mkdir(mode=448, parents=True, exist_ok=True)
    path = directory / 'desired.json'
    temporary = directory / ('.desired-' + secrets.token_hex(5))
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'revision': revision, 'profiles': rows}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = service_status()
        if status and status.get('revision') == revision:
            return
        time.sleep(0.1)
    raise WireGuardError('Telegram proxy did not acknowledge updated access')

def connect_url(node, secret):
    if public(node):
        return 'https://t.me/proxy?' + urlencode({'server': node.host, 'port': node.port, 'secret': node.secret})
    if not managed(node) or not re.fullmatch('[0-9a-f]{32}', secret):
        raise WireGuardError('Telegram proxy access is unavailable')
    return 'https://t.me/proxy?' + urlencode({'server': node.host, 'port': node.port, 'secret': 'dd' + secret})

def load_nodes():
    if not settings.PROXY_NODES.exists():
        return {}
    return parse_nodes(json.loads(settings.PROXY_NODES.read_text()))

def parse_nodes(rows):
    if not isinstance(rows, list):
        raise ValueError('Конфигурация MTProto должна быть списком серверов.')
    (nodes, ids) = ({}, set())
    fields = {'id', 'name', 'host', 'port'}
    for source in rows:
        if not isinstance(source, dict) or set(source) - fields - {'enabled', 'country', 'country_name', 'secret', 'retired', 'checked_at', 'latency_ms'} or fields - set(source):
            raise ValueError('Проверьте поля сервера MTProto.')
        row = {key: source[key] for key in fields}
        if not all((isinstance(row[key], str) for key in ('id', 'name', 'host'))) or type(row['port']) is not int or type(source.get('enabled', True)) is not bool:
            raise ValueError('Проверьте типы параметров MTProto.')
        row.update(country_metadata(source))
        if type(source.get('retired', False)) is not bool:
            raise ValueError('Проверьте статус архивного прокси.')
        row['retired'] = source.get('retired', False)
        if type(source.get('checked_at', 0)) is not int or source.get('checked_at', 0) < 0:
            raise ValueError('Проверьте время проверки прокси.')
        row['checked_at'] = source.get('checked_at', 0)
        latency = source.get('latency_ms', 0)
        if type(latency) not in (float, int) or not math.isfinite(latency) or not 0 <= latency < 60000:
            raise ValueError('Проверьте задержку MTProto.')
        row['latency_ms'] = latency
        if source.get('secret'):
            row['secret'] = normalize_secret(source['secret'])
            if row['id'] == settings.MTPROXY_NODE_ID:
                raise ValueError('Управляемый сервер не использует общий публичный секрет.')
        elif source.get('secret', '') != '':
            raise ValueError('Проверьте секрет MTProto.')
        if not re.fullmatch('[a-z0-9-]{1,30}', row['id']) or row['id'] in ids:
            raise ValueError('Укажите уникальный ID сервера MTProto (до 30 символов).')
        if not row['name'].strip() or len(row['name']) > 80 or any((c in row['name'] for c in '\r\n')):
            raise ValueError('Название сервера: от 1 до 80 символов, одна строка.')
        if not valid_host(row['host']) or not 1 <= row['port'] <= 65535:
            raise ValueError('Укажите IPv4 или домен MTProto и порт от 1 до 65535.')
        ids.add(row['id'])
        if source.get('enabled', True):
            nodes[row['id']] = ProxyNode(**row)
    return nodes
