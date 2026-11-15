"""Refresh the personal Mac endpoint and choose public proxies at live startup."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from html import unescape
from html.parser import HTMLParser
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlsplit
import settings
from backend import proxy, public_proxy
from backend.catalog import country_flag, TELEGRAM_PRIORITY
from backend.geolocation import detect_location, _json, _public_ipv4
from backend.registry import Registry
from backend.service import Problem
from backend.wireguard import WireGuardError
from backend.refresh_schedule import INTERVAL, hourly, scan_lock, require_probe
LIST_URL = 'https://iwizard7.github.io/MTProxy_list/endpoints.json'
SITE_URL = 'https://proxytgfree.online'
PER_COUNTRY = 8
REQUIRED_PUBLIC = set(TELEGRAM_PRIORITY) - {'LT'}
EXTRA_SOURCES = {'Argh94': 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt', 'kort0881': 'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all_mtproto.txt', 'vanced': 'https://vanced.to/telegram', 'tgproxy.pink': 'https://tgproxy.pink/'}
REQUIRED_NAMES = {'RU': 'Россия', 'US': 'США', 'HK': 'Гонконг'}

def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=448)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

def fetch(url):
    with urlopen(Request(url, headers={'User-Agent': 'Northline/1.0'}), timeout=8) as response:
        raw = response.read(2000001)
    if len(raw) > 2000000:
        raise ValueError('Proxy source is too large')
    return raw.decode('utf-8')

def candidate(host, port, secret, hint='', rank=60000):
    try:
        port = int(port)
        secret = proxy.normalize_secret(secret)
        node = proxy.ProxyNode('candidate', 'Candidate', host, port, secret=secret)
        if not proxy.probe_supported(node):
            return None
        from backend.catalog import valid_host
        if not valid_host(host) or not 1 <= port <= 65535:
            return None
        if re.fullmatch('[0-9.]+', host) and (not ipaddress.IPv4Address(host).is_global):
            return None
        rank = float(rank)
        return {'host': host, 'port': port, 'secret': secret, 'hint': hint, 'rank': rank if math.isfinite(rank) and rank > 0 else 60000}
    except (ValueError, TypeError):
        return None

class ProxyPage(HTMLParser):

    def __init__(self):
        super().__init__()
        (self.rows, self.countries, self.current, self.text) = ([], set(), None, [])

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        match = re.fullmatch('/proxy/([a-z]{2})', attrs.get('href', ''))
        if match:
            self.countries.add(match[1])
            if self.current is not None:
                self.current['hint'] = match[1].upper()
        if tag == 'article' and 'data-server' in attrs:
            self.current = {'host': attrs['data-server'], 'port': attrs.get('data-port'), 'secret': attrs.get('data-secret'), 'hint': ''}
            self.text = []

    def handle_data(self, data):
        if self.current is not None:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == 'article' and self.current is not None:
            match = re.search('latency\\s+([0-9.]+)\\s*ms', ' '.join(self.text), re.I)
            row = candidate(**self.current, rank=match[1] if match else 60000)
            if row:
                self.rows.append(row)
            self.current = None

def parse_links(text, hint=''):
    rows = {}
    for link in re.findall('(?:tg://proxy|https://t\\.me/proxy)\\?[^\\s<>"\\)]+', unescape(text)):
        try:
            fields = parse_qs(urlsplit(link).query, max_num_fields=20)
            row = candidate(fields['server'][0], fields['port'][0], fields['secret'][0], hint)
            if row:
                rows[row['host'], row['port'], row['secret']] = row
        except (ValueError, KeyError):
            pass
    return list(rows.values())

def load_extra(name, url):
    text = fetch(url)
    if name == 'vanced':
        rows = []
        cards = re.split('<div\\b[^>]*class=["\\\'][^"\\\']*\\bproxy-card\\b[^"\\\']*["\\\'][^>]*>', text)
        for card in cards[1:]:
            match = re.search('/flags/4x3/([a-z]{2})\\.svg', card)
            if match and match[1].upper() in REQUIRED_PUBLIC:
                rows.extend(parse_links(card, match[1].upper()))
        return rows[:128]
    if name == 'tgproxy.pink':
        rows = []
        for (code, body) in re.findall('<li\\b[^>]*data-country=["\\\']([A-Z]{2})["\\\'][^>]*>(.*?)</li>', text, re.S):
            if code in REQUIRED_PUBLIC:
                rows.extend(parse_links(body, code))
        return rows[:128]
    return parse_links(text)[:512]

def load_reserves():
    try:
        value = json.loads((settings.ROOT / 'data/proxy-reserves.json').read_text())
        rows = value.get('proxies', []) if isinstance(value, dict) else []
        if not isinstance(rows, list):
            return []
        result = []
        for row in rows[:32]:
            if not isinstance(row, dict) or row.get('country') not in REQUIRED_PUBLIC:
                continue
            item = candidate(row.get('host'), row.get('port'), row.get('secret'), row['country'], rank=1)
            if item:
                result.append(item)
        return result
    except (OSError, ValueError):
        return []

def save_reserves(verified):
    rows = []
    for code in sorted(REQUIRED_PUBLIC):
        group = sorted((row for row in verified if row['country'] == code), key=lambda row: row['latency_ms'])
        rows.extend(({key: row[key] for key in ('host', 'port', 'secret', 'country', 'latency_ms')} for row in group[:4]))
    known = {(row['host'], row['port'], row['secret']) for row in rows}
    for old in load_reserves():
        key = (old['host'], old['port'], old['secret'])
        code = old['hint']
        if key not in known and sum((row['country'] == code for row in rows)) < 4:
            rows.append({key: old[key] for key in ('host', 'port', 'secret')} | {'country': code})
            known.add(key)
    atomic_json(settings.ROOT / 'data/proxy-reserves.json', {'proxies': rows})

def discover():
    (rows, errors) = ([], [])

    def load_list():
        value = json.loads(fetch(LIST_URL))
        endpoints = value.get('endpoints') if isinstance(value, dict) else None
        if not isinstance(endpoints, list):
            raise ValueError('Invalid proxy list')
        found = []
        for item in endpoints[:2000]:
            if not isinstance(item, dict) or item.get('verified') is not True:
                continue
            row = candidate(item.get('server'), item.get('port'), item.get('secret'), rank=item.get('median_rtt_ms', item.get('rtt_ms', 60000)))
            if row:
                found.append(row)
        return sorted(found, key=lambda row: (not bool(re.fullmatch('[0-9.]+', row['host'])), row['rank']))[:128]

    def load_site():
        page = ProxyPage()
        page.feed(fetch(SITE_URL + '/'))
        found = list(page.rows)

        def country(code):
            try:
                page = ProxyPage()
                page.feed(fetch(SITE_URL + '/proxy/' + code))
                return page.rows
            except (OSError, ValueError):
                return []
        with ThreadPoolExecutor(max_workers=4) as pool:
            for batch in pool.map(country, sorted(page.countries)[:32]):
                found.extend(batch)
        groups = {}
        for row in found:
            groups.setdefault(row['hint'], []).append(row)
        return [row for group in groups.values() for row in sorted(group, key=lambda row: row['rank'])[:PER_COUNTRY]]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [(name, pool.submit(loader)) for (name, loader) in [('MTProxy_list', load_list), ('proxytgfree', load_site)]]
        futures.extend(((name, pool.submit(load_extra, name, url)) for (name, url) in EXTRA_SOURCES.items()))
        for (name, future) in futures:
            try:
                rows.extend(future.result())
            except (OSError, ValueError):
                errors.append(name + ': unavailable')
    unique = {}
    for row in rows:
        key = (row['host'], row['port'], row['secret'])
        if key not in unique or (row['hint'] and (not unique[key]['hint'])):
            unique[key] = row
    return (list(unique.values()), errors)

def locate_candidate(row):
    location = detect_location(row['host'])
    expected = row.get('hint')
    if location is None and (expected in REQUIRED_PUBLIC or row.get('known_name')):
        try:
            address = _public_ipv4(row['host'])
            if address:
                countries = []
                for (url, field) in [('https://ipapi.co/' + address + '/json/', 'country_code'), ('https://api.country.is/' + address, 'country')]:
                    try:
                        code = _json(url).get(field)
                        if isinstance(code, str) and re.fullmatch('[A-Z]{2}', code):
                            countries.append(code)
                    except (OSError, ValueError, TypeError):
                        pass
                if countries and all((code == expected for code in countries)):
                    location = {'country': expected, 'country_name': REQUIRED_NAMES.get(expected, row.get('known_name'))}
        except (OSError, ValueError, KeyError, TypeError):
            pass
    if not location and row.get('current') and row.get('known_name') and re.fullmatch('[0-9.]+', row['host']) and re.fullmatch('[A-Z]{2}', expected):
        location = {'country': expected, 'country_name': row['known_name']}
    if not location:
        return None
    if location['country'] in REQUIRED_NAMES:
        location = {**location, 'country_name': REQUIRED_NAMES[location['country']]}
    return {**row, **location}

def choose_fastest(rows, verified=None):
    groups = {}
    rows = sorted(rows, key=lambda row: (row.get('hint') not in REQUIRED_PUBLIC, row['rank']))
    with ThreadPoolExecutor(max_workers=8) as pool:
        for row in pool.map(locate_candidate, rows):
            if row:
                groups.setdefault(row['country'], []).append(row)
    shortlist = []
    for group in groups.values():
        shortlist.extend((row for row in group if row.get('current')))
        shortlist.extend(sorted((row for row in group if not row.get('current')), key=lambda row: row['rank'])[:PER_COUNTRY])

    def measure(row):
        node = proxy.ProxyNode('candidate', 'Candidate', row['host'], row['port'], secret=row['secret'])
        try:
            latency = public_proxy.check(node)
            return {**row, 'latency_ms': latency} if math.isfinite(latency) and latency > 0 else None
        except (WireGuardError, OSError, ValueError):
            return None
    winners = {}

    def record(row):
        if not row:
            return
        if verified is not None:
            verified.append(row)
        previous = winners.get(row['country'])
        if previous is None or (row.get('current') and (not previous.get('current'))) or (bool(row.get('current')) == bool(previous.get('current')) and row['latency_ms'] < previous['latency_ms']):
            winners[row['country']] = row
    with ThreadPoolExecutor(max_workers=4) as pool:
        for row in pool.map(measure, shortlist):
            record(row)
        fallback = [row for (code, group) in groups.items() if code not in winners for row in sorted((item for item in group if item not in shortlist), key=lambda row: row['rank'])[:24 if code in REQUIRED_PUBLIC else 8]]
        for row in pool.map(measure, fallback):
            record(row)
    return winners

def refresh_managed(rows):
    node = next((row for row in rows if row['id'] == settings.MTPROXY_NODE_ID and row.get('country') == 'LT' and (not row.get('secret'))), None)
    if not settings.PERSONAL_TEST or not node:
        return None
    if settings.MTPROXY_STATE_DIR.resolve() != (settings.ROOT / 'data/mtproxy').resolve():
        raise ValueError('Personal proxy state directory differs from the local test container')
    env = dict(os.environ)
    docker = shutil.which('docker') or next((p for p in ('/usr/local/bin/docker', '/Applications/Docker.app/Contents/Resources/bin/docker') if Path(p).is_file()), None)
    if not docker:
        raise ValueError('Docker CLI is unavailable')
    env['PATH'] = str(Path(docker).parent) + os.pathsep + env.get('PATH', '')
    for action in ('map', 'start'):
        subprocess.run([sys.executable, str(settings.ROOT / 'deploy/mtproxy-test.py'), action], env=env, capture_output=True, text=True, check=True, timeout=40)
    network = json.loads((settings.MTPROXY_STATE_DIR / 'network.json').read_text())
    address = str(ipaddress.IPv4Address(network['public_ip']))
    if not ipaddress.IPv4Address(address).is_global:
        raise ValueError('Personal proxy requires a public IPv4 address')
    if (settings.MTPROXY_STATE_DIR / 'public-ip').read_text().strip() != address:
        raise ValueError('Public IPv4 changed during startup')
    return {**node, 'host': address}

def managed_health(rows, refreshed=None):
    row = refreshed or next((row for row in rows if row['id'] == settings.MTPROXY_NODE_ID), None)
    if row is None:
        return None
    node = proxy.parse_nodes([{**row, 'retired': False}]).get(row['id'])
    return {**row, 'retired': not bool(node and proxy.available({node.id: node}))}

def same_endpoint(left, right):
    return all((left.get(key) == right.get(key) for key in ('host', 'port', 'secret')))

def apply(vpn, original, revision, winners, managed):
    with vpn.lock:
        registry = Registry(vpn)
        (_, current_revision, raw) = registry.read('telegram')
        if current_revision != revision:
            raise Problem(409, 'Proxy registry changed during refresh; keeping the administrator changes.')
        with vpn.db() as db:
            outstanding = {row[0] for row in db.execute("SELECT DISTINCT node FROM profiles WHERE scope='telegram' AND state IN ('creating','active','revoking')")}
        proposed = []
        used = {managed.get('country')} if managed and (not managed.get('retired')) else set()
        for old in original:
            code = old.get('country')
            if old['id'] == settings.MTPROXY_NODE_ID:
                proposed.append(managed or old)
                if managed and (not managed.get('retired')):
                    used.add(managed.get('country'))
            elif old.get('secret') and old.get('enabled', True):
                winner = winners.get(code)
                if winner and same_endpoint(old, winner) and (code not in used):
                    proposed.append({**old, 'country_name': winner['country_name'], 'retired': False, 'checked_at': int(time.time()), 'latency_ms':winner['latency_ms']})
                    used.add(code)
                elif old['id'] in outstanding:
                    proposed.append({**old, 'retired': True})
            elif old.get('retired') and old['id'] not in outstanding:
                continue
            else:
                proposed.append(old)
        for (code, winner) in sorted(winners.items()):
            if code in used:
                continue
            fingerprint = hashlib.sha256(json.dumps([winner[key] for key in ('host', 'port', 'secret')]).encode()).hexdigest()[:10]
            node_id = 'public-' + code.lower() + '-' + fingerprint
            if any((row['id'] == node_id for row in proposed)):
                raise ValueError('Discovered proxy ID conflicts with an existing server')
            proposed.append({'id': node_id, 'name': country_flag(code) + ' ' + winner['country_name'], 'country': code, 'country_name': winner['country_name'], 'host': winner['host'], 'port': winner['port'], 'secret': winner['secret'], 'enabled': True, 'checked_at': int(time.time()), 'latency_ms':winner['latency_ms']})
        nodes = proxy.parse_nodes(proposed)
        if proposed != original:
            path = settings.PROXY_NODES
            if raw:
                backup = path.parent / 'registry-backups' / (path.stem + '-' + str(time.time_ns()) + '.json')
                atomic_json(backup, original)
            with vpn.db() as db:
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_metrics'").fetchone():
                    for row in original:
                        replacement = next((new for new in proposed if new['id'] == row['id']), None)
                        if replacement is None or not same_endpoint(row, replacement):
                            db.execute("DELETE FROM server_metrics WHERE scope='telegram' AND node=?", (row['id'],))
            atomic_json(path, proposed)
            vpn.catalogs['telegram'] = nodes
        return [{'country': code, 'name': row['country_name'], 'latency_ms': row['latency_ms']} for (code, row) in sorted(winners.items())]

def refresh(vpn):
    with scan_lock(settings.PROXY_NODES) as acquired:
        return _refresh(vpn) if acquired else {'status': 'busy'}

def _refresh(vpn):
    report = {'status': 'running', 'started_at': int(time.time()), 'interval_seconds': INTERVAL, 'sources': [LIST_URL, SITE_URL, *EXTRA_SOURCES.values()], 'errors': []}
    path = settings.ROOT / 'data/proxy-refresh.json'
    try:
        atomic_json(path, report)
        with vpn.lock:
            (original, revision, _) = Registry(vpn).read('telegram')
        require_probe('northline-mtproxy:local')
        try:
            managed = refresh_managed(original)
            report['lithuania'] = 'updated' if managed else 'not configured'
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            managed = None
            report['lithuania'] = 'previous endpoint retained'
            report['errors'].append('Local proxy/IP/port mapping could not be refreshed')
        managed = managed_health(original, managed)
        if managed:
            report['lithuania'] = 'unavailable' if managed.get('retired') else 'verified'
        (rows, errors) = discover()
        rows.extend(load_reserves())
        report['errors'].extend(errors)
        for row in original:
            if row.get('secret') and row.get('enabled', True):
                item = candidate(row['host'], row['port'], row['secret'], row.get('country', ''), rank=1)
                if item:
                    item['known_name'] = row.get('country_name', '')
                    item['current'] = not row.get('retired', False)
                    rows.append(item)
        unique = {(row['host'], row['port'], row['secret']): row for row in rows}
        report['candidates'] = len(unique)
        verified = []
        winners = choose_fastest(list(unique.values()), verified)
        if managed and (not managed.get('retired')):
            winners.pop(managed.get('country'), None)
        try:
            save_reserves(verified)
        except OSError:
            report['errors'].append('Verified proxy reserves could not be saved')
        if not winners:
            report['errors'].append('No public proxy passed the MTProto check')
        report['countries'] = apply(vpn, original, revision, winners, managed)
        report['removed'] = [row['id'] for row in original if not row.get('retired') and (not any((node.id == row['id'] and (not node.retired) for node in vpn.catalogs['telegram'].values())))]
        report['required'] = {code: 'verified' if code in winners else 'missing' for code in REQUIRED_PUBLIC}
        report['required']['LT'] = 'verified' if 'LT' in winners or (managed and (not managed.get('retired'))) else 'missing'
        missing = [code for (code, state) in report['required'].items() if state == 'missing']
        if missing:
            report['errors'].append('Required countries missing: ' + ', '.join(sorted(missing)))
        report['status'] = 'complete' if not report['errors'] else 'partial'
        print('Telegram proxy refresh: ' + str(len(winners)) + ' countries checked; Lithuania ' + report['lithuania'] + '.', flush=True)
    except Exception as error:
        report['status'] = 'failed'
        report['errors'].append(type(error).__name__ + ': previous registry retained')
        print('Telegram proxy refresh failed; keeping the current registry.', flush=True)
    finally:
        report['finished_at'] = int(time.time())
        report['next_check_at'] = report['started_at'] + ((report['finished_at'] - report['started_at']) // INTERVAL + 1) * INTERVAL
        try:
            atomic_json(path, report)
        except OSError:
            print('Could not save proxy refresh status.', flush=True)
    return report

def maintain(vpn):
    hourly(lambda : refresh(vpn))
