"""Keep only the optional Mac test port leases alive, apart from hourly discovery."""
import subprocess
import sys
import time

import settings


def renew(vpn):
    with vpn.lock:
        scripts = []
        if any(node.ssh_host == 'northline-local-node' for node in vpn.nodes.values()):
            scripts.append('pc-test.py')
        if settings.MTPROXY_NODE_ID and settings.MTPROXY_NODE_ID in vpn.catalogs['telegram']:
            scripts.append('mtproxy-test.py')
    for name in scripts:
        try:
            subprocess.run([sys.executable, str(settings.ROOT/'deploy'/name), 'map'],
                           capture_output=True, check=True, timeout=40)
        except (OSError, subprocess.SubprocessError):
            print('Local test port renewal failed; retrying on the next lease cycle.', flush=True)


def maintain(vpn):
    while True:
        renew(vpn)
        time.sleep(15 * 60)
