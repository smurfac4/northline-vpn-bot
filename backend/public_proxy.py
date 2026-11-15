"""Bounded, unauthenticated MTProto checks for explicitly configured public nodes."""
import json
import secrets
import subprocess
import shutil
from pathlib import Path

import settings
from backend import proxy
from backend.geolocation import _public_ipv4
from backend.wireguard import WireGuardError


def check(node):
    if not proxy.probe_supported(node):raise WireGuardError('Unsupported proxy transport')
    try:address=_public_ipv4(node.host)
    except (OSError,ValueError):address=None
    if not address:raise WireGuardError('Public proxy address is unavailable')
    tls=len(node.secret)>34 and node.secret.startswith('ee')
    secure=len(node.secret)==34
    payload={'host':address,'port':node.port,'secret':node.secret[2:] if secure else node.secret,
             'transport':'tls' if tls else 'secure' if secure else 'intermediate'}
    name='northline-public-check-'+secrets.token_hex(6)
    docker=shutil.which('docker') or next((path for path in ('/usr/local/bin/docker','/Applications/Docker.app/Contents/Resources/bin/docker') if Path(path).is_file()),'docker')
    try:
        code=(settings.ROOT/'deploy/mtproxy/faketls.py').read_text()+'\n'+(settings.ROOT/'deploy/mtproxy/probe.py').read_text()
        result=subprocess.run([docker,'run','--rm','-i','--name',name,'--label','org.northline.public-check=1',
            '--network','bridge','--cap-drop','ALL','--memory','128m','--cpus','1','--pids-limit','32',
            '--entrypoint','python3','northline-mtproxy:local','-c',code],input=json.dumps(payload),
            capture_output=True,text=True,timeout=15,check=True)
        data=json.loads(result.stdout)
        elapsed=data.get('roundtrip_ms')
        if data.get('telegram_response')!='resPQ' or data.get('nonce_verified') is not True or type(elapsed) not in (int,float) or not 0<elapsed<60000:
            raise ValueError('Invalid proxy response')
        return float(elapsed)
    except (subprocess.SubprocessError,OSError,ValueError) as error:
        print('Public proxy check failed ('+type(error).__name__+').',flush=True)
        raise WireGuardError('Public MTProto check failed') from None
    finally:
        try:subprocess.run([docker,'rm','-f',name],capture_output=True,timeout=5)
        except (OSError,subprocess.SubprocessError):pass
