"""Small client-side probe, run only inside a dedicated bridge-network container."""
import ipaddress
import json
from pathlib import Path
import subprocess
import sys


def run(*args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=10,**kwargs).stdout.strip()


def main():
    data=json.load(sys.stdin)
    endpoint=str(ipaddress.IPv4Address(data['endpoint']))
    address=str(ipaddress.IPv4Interface(data['address']))
    run('ip','link','add','wgprobe','type','wireguard')
    run('ip','address','add',address,'dev','wgprobe')
    key=Path('/tmp/probe.key');key.write_text(data['private']);key.chmod(0o600)
    run('wg','set','wgprobe','private-key',str(key),'peer',data['server'],'endpoint',endpoint+':51820',
        'allowed-ips','1.0.0.1/32','persistent-keepalive','5')
    run('ip','link','set','wgprobe','mtu','1380','up')
    # A single probe destination only: default route and DNS are preserved.
    run('ip','route','add','1.0.0.1/32','dev','wgprobe')
    trace=run('curl','-4','--interface','wgprobe','--connect-timeout','5','--max-time','10','-fsS',
        '--resolve','one.one.one.one:443:1.0.0.1','https://one.one.one.one/cdn-cgi/trace')
    values=dict(line.split('=',1) for line in trace.splitlines() if '=' in line)
    handshake=run('wg','show','wgprobe','latest-handshakes').split()
    transfer=run('wg','show','wgprobe','transfer').split()
    result={'egress_ip':values.get('ip'),'handshake':int(handshake[1]),'rx_bytes':int(transfer[1]),'tx_bytes':int(transfer[2])}
    if not result['handshake'] or not result['rx_bytes'] or not result['tx_bytes']:raise RuntimeError('WireGuard probe did not exchange traffic')
    print(json.dumps(result))


if __name__=='__main__':main()
