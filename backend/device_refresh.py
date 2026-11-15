"""Refresh only public whole-device VPNs; no Telegram registry or transport changes."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import secrets
import time
import settings
from backend import device_vpn
from backend.catalog import country_flag
from backend.geolocation import detect_location, _json
from backend.wireguard import WireGuardError
from backend.refresh_schedule import INTERVAL, hourly, scan_lock, require_probe

def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=448)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

def read_registry():
    raw = settings.DEVICE_NODES.read_bytes() if settings.DEVICE_NODES.exists() else b''
    rows = json.loads(raw) if raw else []
    device_vpn.parse_nodes(rows)
    return (rows, hashlib.sha256(raw).hexdigest())

def check_candidates(rows, verified=None):
    groups = {}
    unique = {row['id']: row for row in rows}
    for row in unique.values():
        if not row.get('retired'):
            groups.setdefault(row['country'], []).append(row)
    groups = {code: sorted(group, key=lambda row: (row.get('priority', 2), -row.get('source_speed', 0), row.get('source_ping', 60000))) for (code, group) in groups.items()}
    ordered = sorted(groups, key=lambda code: code not in device_vpn.REQUIRED_COUNTRIES)
    shortlist = []
    for code in ordered:
        shortlist.extend((row for row in groups[code] if row.get('current')))
        shortlist.extend([row for row in groups[code] if not row.get('current')][:2])

    def check(row):
        try:
            node = device_vpn.parse_nodes([row])[row['id']]
            result = device_vpn.check(node)
            location = egress_location(result['egress_ip'])
            if location is None and row.get('current') and (result['egress_ip'] == row.get('egress_ip')):
                location = {'country': row['country'], 'country_name': row['country_name']}
            if location is None:
                return None
            code = location['country']
            name = device_vpn.COUNTRY_NAMES.get(code, location.get('country_name') or code)
            return {key: row[key] for key in ('endpoint', 'config')} | {'id': 'ovpn-' + code.lower() + '-' + hashlib.sha256(row['config'].encode()).hexdigest()[:12], 'country': code, 'country_name': name, 'name': country_flag(code) + ' ' + name, 'current': bool(row.get('current')), 'checked_at': int(time.time()), 'latency_ms': result['latency_ms'], 'egress_ip': result['egress_ip']}
        except (WireGuardError, ValueError, OSError):
            return None
    winners = {}
    verified = verified if verified is not None else []

    def record(row):
        if row:
            verified.append(row)
            previous = winners.get(row['country'])
            if previous is None or (row.get('current') and (not previous.get('current'))) or (bool(row.get('current')) == bool(previous.get('current')) and row['latency_ms'] < previous['latency_ms']):
                winners[row['country']] = row
    count = len(shortlist)
    with ThreadPoolExecutor(max_workers=3) as pool:
        for row in pool.map(check, shortlist):
            record(row)
        for code in device_vpn.REQUIRED_COUNTRIES:
            pending = [row for row in groups.get(code, []) if row not in shortlist][:30]
            for index in range(0, len(pending), 3):
                if len({row['egress_ip'] for row in verified if row['country'] == code}) >= 3:
                    break
                batch = pending[index:index + 3]
                count += len(batch)
                for row in pool.map(check, batch):
                    record(row)
        fallback = [row for (code, group) in groups.items() if code not in winners and code not in device_vpn.REQUIRED_COUNTRIES for row in [item for item in group if item not in shortlist][:14]]
        for row in pool.map(check, fallback):
            record(row)
    return (winners, count + len(fallback))

def load_reserves():
    try:
        rows = json.loads((settings.ROOT / 'data/device-vpn-reserves.json').read_text())
        device_vpn.parse_nodes(rows)
        return [{**row, 'priority': 0} for row in rows if row['country'] in device_vpn.REQUIRED_COUNTRIES]
    except (OSError, ValueError, TypeError):
        return []

def save_reserves(verified):
    rows = []
    for code in device_vpn.REQUIRED_COUNTRIES:
        group = sorted((row for row in verified if row['country'] == code), key=lambda row: row['latency_ms'])
        seen = set()
        for row in [*group, *load_reserves()]:
            if row['country'] != code or row['egress_ip'] in seen:
                continue
            rows.append({key: row[key] for key in ('id', 'name', 'country', 'country_name', 'endpoint', 'config', 'checked_at', 'latency_ms', 'egress_ip')})
            seen.add(row['egress_ip'])
            if len(seen) >= 4:
                break
    atomic_json(settings.ROOT / 'data/device-vpn-reserves.json', rows)

def egress_location(address):
    location = detect_location(address)
    if location:
        return location
    try:
        code = _json('https://api.country.is/' + address).get('country')
        if isinstance(code, str) and len(code) == 2 and code.isascii() and code.isalpha() and code.isupper():
            return {'country': code, 'country_name': device_vpn.COUNTRY_NAMES.get(code, code)}
    except (OSError, ValueError, TypeError):
        pass
    return None

def apply(vpn, original, revision, winners):
    with vpn.lock:
        (_, current) = read_registry()
        if current != revision:
            raise ValueError('Device VPN registry changed during refresh')
        with vpn.db() as db:
            outstanding = {row[0] for row in db.execute("SELECT DISTINCT node FROM profiles WHERE scope='device' AND state IN ('creating','active','revoking')")}
        proposed = [{key: value for (key, value) in row.items() if key != 'current'} for row in winners.values()]
        selected = {row['id'] for row in proposed}
        for old in original:
            if old['id'] in selected:
                continue
            if old['id'] in outstanding:
                proposed.append({**old, 'retired': True})
        nodes = device_vpn.parse_nodes(proposed)
        if proposed != original:
            if original:
                atomic_json(settings.DEVICE_NODES.parent / 'registry-backups' / ('device-vpn-' + str(time.time_ns()) + '.json'), original)
            atomic_json(settings.DEVICE_NODES, proposed)
        with vpn.db() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_metrics'").fetchone():
                for row in winners.values():
                    db.execute("DELETE FROM server_metrics WHERE scope='device' AND node=?", (row['id'],))
        vpn.catalogs['device'] = {**vpn.nodes, **nodes}

def refresh(vpn):
    with scan_lock(settings.DEVICE_NODES) as acquired:
        return _refresh(vpn) if acquired else {'status': 'busy'}

def _refresh(vpn):
    path = settings.ROOT / 'data/device-vpn-refresh.json'
    report = {'status': 'running', 'source': device_vpn.SOURCE, 'sources': [device_vpn.SOURCE, device_vpn.RUSSIA_SOURCE], 'started_at': int(time.time()), 'interval_seconds': INTERVAL, 'errors': []}
    try:
        atomic_json(path, report)
        with vpn.lock:
            (original, revision) = read_registry()
        require_probe('northline-openvpn-probe:local')
        candidates = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [(name, pool.submit(loader)) for (name, loader) in [('VPN Gate', device_vpn.fetch_candidates), ('Russian VPN source', device_vpn.fetch_russian_candidates)]]
            for (name, future) in futures:
                try:
                    rows = future.result()
                    if not rows:
                        raise ValueError('No usable configs')
                    candidates.extend(rows)
                except (OSError, ValueError):
                    report['errors'].append(name + ' could not be refreshed; checking saved device VPNs')
        candidates.extend(load_reserves())
        candidates.extend(({**row, 'priority': 0, 'current': not row.get('retired', False), 'retired': False} for row in original))
        report['candidates'] = len({row['id'] for row in candidates})
        verified = []
        (winners, count) = check_candidates(candidates, verified)
        try:
            save_reserves(verified)
        except OSError:
            report['errors'].append('Required device VPN reserves could not be saved')
        report['checked'] = count
        apply(vpn, original, revision, winners)
        with vpn.lock:
            current = list(vpn.catalogs['device'].values())
        report['removed'] = [row['id'] for row in original if not row.get('retired') and (not any((node.id == row['id'] and (not node.retired) for node in current if device_vpn.public(node))))]
        report['countries'] = [{key: row[key] for key in ('country', 'country_name', 'endpoint', 'latency_ms', 'egress_ip')} for (_, row) in sorted(winners.items())]
        if not winners:
            report['errors'].append('No whole-device VPN tunnel passed the connection and HTTPS test')
        report['required'] = {code: 'verified' if code in winners else 'missing' for code in device_vpn.REQUIRED_COUNTRIES}
        if any((state != 'verified' for state in report['required'].values())):
            report['errors'].append('Required device country RU did not pass the tunnel and exit-IP check')
        report['status'] = 'complete' if not report['errors'] else 'partial'
        print('Whole-device VPN refresh: ' + str(len(winners)) + ' countries verified through OpenVPN.', flush=True)
    except Exception as error:
        report['status'] = 'failed'
        report['errors'].append(type(error).__name__ + ': public device VPN registry retained')
        print('Whole-device VPN refresh failed; previous registry retained.', flush=True)
    finally:
        report['finished_at'] = int(time.time())
        report['next_check_at'] = report['started_at'] + ((report['finished_at'] - report['started_at']) // INTERVAL + 1) * INTERVAL
        try:
            atomic_json(path, report)
        except OSError:
            print('Could not save device VPN refresh status.', flush=True)
    return report

def maintain(vpn):
    hourly(lambda : refresh(vpn))
if __name__ == '__main__':
    from backend.service import VPN
    refresh(VPN())
