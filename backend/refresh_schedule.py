"""Hourly maintenance without overlapping scans or accumulating execution-time drift."""
from contextlib import contextmanager
import fcntl
import os
import shutil
import subprocess
import secrets
from pathlib import Path
import time

INTERVAL = 3600


def require_probe(image):
    docker = shutil.which('docker') or next((path for path in ('/usr/local/bin/docker', '/Applications/Docker.app/Contents/Resources/bin/docker')
                                           if Path(path).is_file()), 'docker')
    name = 'northline-runtime-check-' + secrets.token_hex(5)
    try:
        subprocess.run([docker, 'image', 'inspect', image], capture_output=True, check=True, timeout=10)
        flags = ['--network','none','--cap-drop','ALL','--memory','64m','--pids-limit','32']
        code = """try:
 from Crypto.Cipher import AES
except ImportError:
 from Cryptodome.Cipher import AES
import ssl, socket"""
        if image == 'northline-openvpn-probe:local':
            flags += ['--cap-add','NET_ADMIN','--device','/dev/net/tun']
            code = ("import os, subprocess; os.close(os.open('/dev/net/tun',os.O_RDWR)); "
                    "subprocess.run(['ip','link','add','nl-smoke','type','dummy'],check=True,capture_output=True); "
                    "subprocess.run(['openvpn','--version'],check=True,capture_output=True)")
        subprocess.run([docker,'run','--rm','--name',name,*flags,'--entrypoint','python3',image,'-c',code],
                       capture_output=True,check=True,timeout=15)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError('VPN probe runtime is unavailable; catalog was not changed') from None
    finally:
        try:
            subprocess.run([docker,'rm','-f',name],capture_output=True,timeout=5)
        except (OSError,subprocess.SubprocessError):
            pass


def hourly(job):
    deadline = time.monotonic()
    while True:
        try:
            job()
        except Exception:
            print('Scheduled VPN refresh failed; the next hourly scan remains scheduled.', flush=True)
        deadline += INTERVAL
        now = time.monotonic()
        if deadline <= now:
            deadline += (int((now - deadline) // INTERVAL) + 1) * INTERVAL
        time.sleep(max(0, deadline - now))


@contextmanager
def scan_lock(registry):
    path = registry.with_suffix('.refresh.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)
