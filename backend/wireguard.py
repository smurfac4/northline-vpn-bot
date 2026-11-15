import base64
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
import settings
from backend.catalog import valid_host, country_metadata

def valid_key(value):
    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False

@dataclass(frozen=True)
class Node:
    id: str
    name: str
    subnet: ipaddress.IPv4Network
    endpoint: str = ''
    public_key: str = ''
    ssh_host: str = ''
    country: str = ''
    country_name: str = ''

def load_nodes():
    if not settings.NODES.exists():
        return {}
    return parse_nodes(json.loads(settings.NODES.read_text()), allow_empty=True)

def parse_nodes(rows, allow_empty=False):
    if not isinstance(rows, list):
        raise ValueError('Конфигурация WireGuard должна быть списком серверов.')
    (nodes, ids, networks) = ({}, set(), [])
    fields = {'id', 'name', 'subnet', 'endpoint', 'public_key', 'ssh_host'}
    for source in rows:
        if not isinstance(source, dict) or set(source) - fields - {'enabled', 'country', 'country_name'} or fields - set(source):
            raise ValueError('Проверьте поля сервера WireGuard.')
        row = {key: source[key] for key in fields}
        if not all((isinstance(value, str) for value in row.values())) or type(source.get('enabled', True)) is not bool:
            raise ValueError('Параметры WireGuard должны быть строками, статус — переключателем.')
        row.update(country_metadata(source))
        if not re.fullmatch('[a-z0-9-]{1,30}', row['id']) or row['id'] in ids or row['id'].startswith('ovpn-'):
            raise ValueError('ID сервера должен быть уникальным: латинские буквы, цифры и дефисы, до 30 символов.')
        if not row['name'].strip() or len(row['name']) > 80 or any((c in row['name'] for c in '\r\n')):
            raise ValueError('Название сервера: от 1 до 80 символов, одна строка.')
        if not re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', row['ssh_host']):
            raise ValueError('Укажите SSH-алиас: латинские буквы, цифры и дефисы.')
        match = re.fullmatch('([A-Za-z0-9][A-Za-z0-9.-]*):([0-9]{1,5})', row['endpoint'])
        if not match or not valid_host(match[1]) or (not 1 <= int(match[2]) <= 65535):
            raise ValueError('Адрес WireGuard: IPv4 или домен и порт от 1 до 65535.')
        if not valid_key(row['public_key']):
            raise ValueError('Публичный ключ WireGuard должен содержать 32 байта в base64.')
        try:
            network = ipaddress.IPv4Network(row['subnet'])
        except (ValueError, TypeError):
            raise ValueError('Укажите корректную подсеть IPv4 /24.') from None
        if network.prefixlen != 24 or not any((network.subnet_of(ipaddress.IPv4Network(prefix)) for prefix in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))):
            raise ValueError('Используйте частную подсеть /24, например 10.77.0.0/24.')
        if source.get('enabled', True) and any((network.overlaps(other) for other in networks)):
            raise ValueError('Подсети включённых серверов не должны пересекаться.')
        ids.add(row['id'])
        row['subnet'] = network
        if source.get('enabled', True):
            networks.append(network)
            nodes[row['id']] = Node(**row)
    if not nodes and (not allow_empty):
        raise ValueError('Добавьте хотя бы один включённый сервер WireGuard.')
    return nodes

class WireGuardError(Exception):
    pass

def run(*args, data=None):
    try:
        return subprocess.run(args, input=data, capture_output=True, text=True, check=True, timeout=12).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise WireGuardError(f'{args[0]} operation failed') from error

def keys():
    private = run(settings.WG_BIN, 'genkey')
    return (private, run(settings.WG_BIN, 'pubkey', data=private + '\n'))

def control(node, *words):
    config = ['-F', settings.SSH_CONFIG] if settings.SSH_CONFIG else []
    return run('ssh', *config, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes', node.ssh_host, *words)

def client_config(node, private, address):
    mtu = 'MTU = 1380\n' if settings.PERSONAL_TEST else ''
    return f'[Interface]\nPrivateKey = {private}\nAddress = {address}/32\nDNS = 1.1.1.1\n{mtu}\n[Peer]\nPublicKey = {node.public_key}\nEndpoint = {node.endpoint}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n'
