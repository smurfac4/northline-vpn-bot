"""An ephemeral OpenVPN client: only its Docker network namespace is changed."""
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    data = json.load(sys.stdin)
    config = Path('/tmp/client.ovpn'); config.write_text(data['config']); config.chmod(0o600)
    log = Path('/tmp/openvpn.log')
    started = time.monotonic()
    process = subprocess.Popen(['openvpn','--config',str(config),'--dev','tun0','--connect-retry-max','1',
                                '--connect-timeout','7','--tls-timeout','4','--hand-window','12',
                                '--resolv-retry','0','--verb','2','--log',str(log)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = started + 22
        while time.monotonic() < deadline:
            text = log.read_text(errors='replace') if log.exists() else ''
            if 'Initialization Sequence Completed' in text:
                break
            if process.poll() is not None:
                raise RuntimeError('OpenVPN could not establish a verified tunnel')
            time.sleep(.1)
        else:
            raise RuntimeError('OpenVPN tunnel timed out')
        connected = time.monotonic()
        response = subprocess.run(['curl','-4','--interface','tun0','--connect-timeout','5','--max-time','9','-fsS',
                                   '--resolve','one.one.one.one:443:1.0.0.1','https://one.one.one.one/cdn-cgi/trace'],
                                  check=True, capture_output=True, text=True, timeout=10)
        trace = dict(line.split('=',1) for line in response.stdout.splitlines() if '=' in line)
        address = str(ipaddress.IPv4Address(trace['ip']))
        if not ipaddress.IPv4Address(address).is_global:
            raise RuntimeError('VPN did not provide public egress')
        print(json.dumps({'tunnel_established': True, 'egress_ip': address,
                          'connect_ms': round((connected-started)*1000,1),
                          'latency_ms': round((time.monotonic()-connected)*1000,1)}))
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)


if __name__ == '__main__':
    main()
