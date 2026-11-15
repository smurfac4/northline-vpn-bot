"""Public OpenVPN access for the device scope, independent of MTProto."""
import base64
import csv
from dataclasses import dataclass, field
import hashlib
import io
import ipaddress
import json
import math
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen
import settings
from backend.catalog import country_flag, country_metadata
from backend.wireguard import WireGuardError
SOURCE = 'https://www.vpngate.net/api/iphone/'
RUSSIA_SOURCE = 'https://vpnobratno.info/russia_server_list_en.html'
REQUIRED_COUNTRIES = ('RU',)
NOTICE = 'Публичный VPN Gate внешнего оператора. Оператор ведёт журналы подключений. Удаление профиля в боте не отзывает общую конфигурацию; отключите VPN в OpenVPN Connect.'
CIPHERS = {'AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM', 'CHACHA20-POLY1305'}
COUNTRY_NAMES = {'AU': 'Австралия', 'CA': 'Канада', 'JP': 'Япония', 'KR': 'Южная Корея', 'RO': 'Румыния', 'TH': 'Таиланд', 'UA': 'Украина', 'VN': 'Вьетнам', 'RU': 'Россия', 'US': 'США', 'FR': 'Франция', 'IN': 'Индия', 'MM': 'Мьянма', 'AR': 'Аргентина', 'BR': 'Бразилия', 'DE': 'Германия', 'GB': 'Великобритания', 'NL': 'Нидерланды', 'FI': 'Финляндия', 'HK': 'Гонконг'}

@dataclass(frozen=True)
class Node:
    id: str
    name: str
    country: str
    country_name: str
    endpoint: str
    config: str = field(repr=False)
    checked_at: int = 0
    latency_ms: float = 0
    egress_ip: str = ''
    retired: bool = False

def public(node):
    return isinstance(node, Node)

def available(node):
    return not node.retired and 0 <= time.time() - node.checked_at <= 7200

def sanitize_config(raw):
    """Accept a small OpenVPN subset; never distribute scripts, plugins or file paths."""
    if not isinstance(raw, str) or not 0 < len(raw.encode()) <= 65536 or '\x00' in raw:
        raise ValueError('Invalid OpenVPN configuration size')
    (blocks, current, body, options) = ({}, None, [], {})
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if current:
            if line == '</' + current + '>':
                value = '\n'.join(body)
                if not re.fullmatch('[A-Za-z0-9+/=\\s-]+', value) or '-----BEGIN ' not in value or '-----END ' not in value:
                    raise ValueError('Invalid inline certificate/key')
                blocks[current] = value
                (current, body) = (None, [])
            else:
                body.append(line)
            continue
        if line.startswith('<'):
            match = re.fullmatch('<(ca|cert|key)>', line)
            if not match or match[1] in blocks:
                raise ValueError('Unsupported OpenVPN inline block')
            current = match[1]
            continue
        words = line.split()
        (key, args) = (words[0], words[1:])
        if key in options:
            raise ValueError('Duplicate OpenVPN directive')
        if key == 'dev' and args == ['tun']:
            pass
        elif key == 'proto' and args in (['tcp'], ['tcp-client'], ['udp']):
            pass
        elif key == 'remote' and len(args) == 2:
            address = ipaddress.IPv4Address(args[0])
            if not address.is_global or not args[1].isascii() or (not args[1].isdigit()) or (not 1 <= int(args[1]) <= 65535):
                raise ValueError('OpenVPN remote must be a public IPv4 and port')
        elif key in ('cipher', 'data-ciphers') and len(args) == 1 and (set(args[0].split(':')) <= CIPHERS):
            pass
        elif key == 'auth' and args in (['SHA1'], ['SHA256'], ['SHA512']):
            pass
        elif key in ('client', 'nobind', 'persist-key', 'persist-tun', 'auth-nocache') and (not args):
            pass
        elif key == 'verb' and len(args) == 1 and (args[0] in ('0', '1', '2', '3', '4')):
            pass
        elif key == 'resolv-retry' and args == ['infinite']:
            pass
        elif key == 'remote-cert-tls' and args == ['server']:
            pass
        elif key == 'tls-version-min' and args == ['1.2']:
            pass
        elif key == 'redirect-gateway' and args == ['def1']:
            pass
        elif key == 'dhcp-option' and args == ['DNS', '1.1.1.1']:
            pass
        else:
            raise ValueError('Unsupported OpenVPN directive: ' + key)
        options[key] = args
    if current or not {'ca', 'cert', 'key'} <= blocks.keys() or (not {'client', 'dev', 'proto', 'remote'} <= options.keys()):
        raise ValueError('Incomplete OpenVPN configuration')
    cipher = options.get('cipher', ['AES-128-CBC'])[0]
    lines = ['client', 'dev tun', 'proto ' + options['proto'][0], 'remote ' + ' '.join(options['remote']), 'nobind', 'persist-key', 'persist-tun', 'remote-cert-tls server', 'tls-version-min 1.2', 'cipher ' + cipher, 'data-ciphers AES-256-GCM:AES-128-GCM:' + cipher, 'auth ' + options.get('auth', ['SHA256'])[0], 'auth-nocache', 'redirect-gateway def1', 'dhcp-option DNS 1.1.1.1', 'verb 3']
    lines.extend(('<' + key + '>\n' + blocks[key] + '\n</' + key + '>' for key in ('ca', 'cert', 'key')))
    return ('\n'.join(lines) + '\n', options['remote'][0] + ':' + options['remote'][1])

def parse_source(raw):
    if not isinstance(raw, str) or not raw.startswith('*vpn_servers') or len(raw) > 8000000:
        raise ValueError('Invalid VPN Gate directory')
    lines = raw.splitlines()
    header = next((index for (index, line) in enumerate(lines) if line.startswith('#HostName,')), None)
    if header is None:
        raise ValueError('Missing VPN Gate CSV header')
    rows = csv.DictReader(io.StringIO('\n'.join([lines[header][1:], *lines[header + 1:]])))
    nodes = {}
    for row in rows:
        if len(nodes) >= 500:
            break
        try:
            code = row['CountryShort']
            name = COUNTRY_NAMES.get(code, row['CountryLong'])
            location = country_metadata({'country': code, 'country_name': name})
            advertised = ipaddress.IPv4Address(row['IP'])
            if not advertised.is_global:
                continue
            encoded = row['OpenVPN_ConfigData_Base64']
            if not isinstance(encoded, str) or len(encoded) > 90000:
                continue
            (config, endpoint) = sanitize_config(base64.b64decode(encoded, validate=True).decode('utf-8'))
            digest = hashlib.sha256(config.encode()).hexdigest()[:12]
            node_id = 'ovpn-' + code.lower() + '-' + digest
            (speed, ping) = (int(row['Speed']), float(row['Ping']))
            if not math.isfinite(ping) or speed < 0:
                continue
            nodes[node_id] = {'id': node_id, 'name': country_flag(code) + ' ' + name, **location, 'endpoint': endpoint, 'config': config, 'source_speed': speed, 'source_ping': ping if ping >= 0 else 60000}
        except (ValueError, TypeError, KeyError):
            continue
    return list(nodes.values())

def fetch_candidates():
    with urlopen(Request(SOURCE, headers={'User-Agent': 'Northline/1.0'}), timeout=12) as response:
        raw = response.read(8000001)
    if len(raw) > 8000000:
        raise ValueError('VPN Gate directory is too large')
    return parse_source(raw.decode('utf-8-sig'))

class RussianConfigLinks(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag != 'a':
            return
        href = dict(attrs).get('href', '')
        url = urlsplit(urljoin(RUSSIA_SOURCE, href))
        if url.scheme != 'https' or url.netloc != 'vpnobratno.info' or url.query or url.fragment:
            return
        if not re.fullmatch('/servers/(vpn[0-9]{1,12}\\.opengw\\.net)/\\1_ip_(udp|tcp)\\.ovpn', url.path):
            return
        link = 'https://vpnobratno.info' + url.path
        if link not in self.links and len(self.links) < 32:
            self.links.append(link)

def fetch_russian_candidates():
    with urlopen(Request(RUSSIA_SOURCE, headers={'User-Agent': 'Northline/1.0'}), timeout=10) as response:
        raw = response.read(500001)
    if len(raw) > 500000:
        raise ValueError('Russian VPN directory is too large')
    parser = RussianConfigLinks()
    parser.feed(raw.decode('utf-8'))

    def load(url):
        try:
            with urlopen(Request(url, headers={'User-Agent': 'Northline/1.0'}), timeout=8) as response:
                raw = response.read(65537)
            (config, endpoint) = sanitize_config(raw.decode('utf-8'))
            digest = hashlib.sha256(config.encode()).hexdigest()[:12]
            return {'id': 'ovpn-ru-' + digest, 'name': '🇷🇺 Россия', 'country': 'RU', 'country_name': 'Россия', 'endpoint': endpoint, 'config': config, 'priority': 1}
        except (OSError, ValueError):
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = [row for row in pool.map(load, parser.links) if row]
    return list({row['id']: row for row in rows}.values())

def parse_nodes(rows):
    if not isinstance(rows, list):
        raise ValueError('Public device VPN registry must be a list')
    result = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or (not re.fullmatch('ovpn-[a-z]{2}-[0-9a-f]{12}', row['id'])) or (row['id'] in result):
            raise ValueError('Invalid public device VPN ID')
        country_metadata(row)
        if not isinstance(row.get('config'), str) or len(row['config']) > 65536:
            raise ValueError('Invalid public device VPN config')
        (canonical, endpoint) = sanitize_config(row['config'])
        if canonical != row['config'] or endpoint != row.get('endpoint'):
            raise ValueError('Stored OpenVPN configuration is not canonical')
        digest = hashlib.sha256(row['config'].encode()).hexdigest()[:12]
        if row['id'] != 'ovpn-' + row['country'].lower() + '-' + digest:
            raise ValueError('Public device VPN config digest changed')
        if not isinstance(row.get('endpoint'), str) or not isinstance(row.get('name'), str) or (not 0 < len(row['name']) <= 100):
            raise ValueError('Invalid public device VPN metadata')
        if type(row.get('checked_at', 0)) is not int or type(row.get('retired', False)) is not bool:
            raise ValueError('Invalid public device VPN status')
        latency = row.get('latency_ms', 0)
        if type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0:
            raise ValueError('Invalid public device VPN latency')
        result[row['id']] = Node(**{key: row[key] for key in ('id', 'name', 'country', 'country_name', 'endpoint', 'config')}, checked_at=row.get('checked_at', 0), latency_ms=latency, egress_ip=row.get('egress_ip', ''), retired=row.get('retired', False))
    return result

def load_nodes():
    if not settings.DEVICE_NODES.exists():
        return {}
    return parse_nodes(json.loads(settings.DEVICE_NODES.read_text()))

def check(node):
    name = 'northline-openvpn-check-' + secrets.token_hex(6)
    docker = shutil.which('docker') or next((path for path in ('/usr/local/bin/docker', '/Applications/Docker.app/Contents/Resources/bin/docker') if Path(path).is_file()), 'docker')
    try:
        code = (settings.ROOT / 'deploy/device-probe/probe.py').read_text()
        response = subprocess.run([docker, 'run', '--rm', '-i', '--name', name, '--label', 'org.northline.device-check=1', '--network', 'bridge', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun', '--memory', '128m', '--cpus', '1', '--pids-limit', '32', '--entrypoint', 'python3', 'northline-openvpn-probe:local', '-c', code], input=json.dumps({'config': node.config}), capture_output=True, text=True, check=True, timeout=40)
        data = json.loads(response.stdout)
        if data.get('tunnel_established') is not True or not ipaddress.IPv4Address(data['egress_ip']).is_global:
            raise ValueError('No public VPN egress')
        if type(data.get('latency_ms')) not in (float, int) or not math.isfinite(data['latency_ms']) or (not 0 < data['latency_ms'] < 30000):
            raise ValueError('Invalid VPN probe latency')
        return data
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise WireGuardError('Public device VPN tunnel check failed') from None
    finally:
        try:
            subprocess.run([docker, 'rm', '-f', name], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass

def instructions(platform):
    return ['Установите OpenVPN Connect на ' + {'ios': 'iPhone / iPad', 'android': 'Android', 'windows': 'Windows', 'macos': 'macOS', 'linux': 'Linux', 'other': 'ваше устройство'}[platform] + '.', 'Скачайте файл .ovpn и импортируйте его в OpenVPN Connect.', 'Включите VPN в приложении и разрешите создание VPN-подключения на устройстве.', 'После смены сервера скачайте и импортируйте новый файл .ovpn.']
