"""Run the MTProto proxy with the current unexpired, individually issued secrets."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import time
from metrics import collect

STATE=Path('/state')


def atomic(path,value):
    temporary=path.with_name('.'+path.name+'.'+secrets.token_hex(5))
    try:
        with temporary.open('w') as stream:json.dump(value,stream)
        temporary.chmod(0o600);temporary.replace(path)
    finally:
        if temporary.exists():temporary.unlink()


def stop(process):
    if not process:return
    try:os.killpg(process.pid,signal.SIGTERM)
    except ProcessLookupError:pass
    try:process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait(timeout=2)
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass



def main():
    os.umask(0o077);STATE.mkdir(exist_ok=True)
    process=None;current=None;revision=None;healthy_since=0;log=None
    metrics=None;next_sample=0;sample_id=None
    def interrupt(*_):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupt)
    fallback=secrets.token_hex(16)
    try:
        while True:
            desired=json.loads((STATE/'desired.json').read_text()) if (STATE/'desired.json').exists() else {'revision':'empty','profiles':[]}
            now=int(time.time());active=[]
            for row in desired['profiles']:
                if type(row.get('expires')) is not int or not re.fullmatch('[0-9a-f]{32}',row.get('secret','')):raise ValueError('Invalid proxy access state')
                if row['expires']==0 or row['expires']>now:active.append(row['secret'])
            if len(active)>16:raise ValueError('Proxy capacity exceeded')
            public=(STATE/'public-ip').read_text().strip()
            fingerprint=hashlib.sha256(json.dumps([active,public]).encode()).hexdigest()
            if fingerprint!=current or process is None or process.poll() is not None:
                stop(process)
                if log:log.close()
                log=(STATE/'process.log').open('a')
                config=STATE/'runtime-config.py'
                users={f'profile{index}':secret for index,secret in enumerate(active or [fallback])}
                config.write_text('PORT = 8443\nUSERS = '+repr(users)+'\n'
                    'MODES = {"classic": False, "secure": True, "tls": False}\n'
                    'USE_MIDDLE_PROXY = False\nPREFER_IPV6 = False\nLISTEN_ADDR_IPV6 = False\n'
                    'METRICS_PORT = 8888\nMETRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"\nMETRICS_EXPORT_LINKS = False\n'
                    'MY_DOMAIN = '+repr(public)+'\n')
                environment=dict(os.environ);environment['NORTHLINE_PROXY_IP']=public
                args=['python3','/app/run_proxy.py',str(config)]
                process=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=environment)
                current=fingerprint;healthy_since=time.monotonic()+.5
                metrics=None;next_sample=0;sample_id=secrets.token_hex(8)
            revision=desired['revision']
            if time.monotonic()>=healthy_since and process.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1',8443),timeout=.2):pass
                except OSError:pass
                else:
                    if time.monotonic()>=next_sample:
                        try:metrics={**collect(),'sampled_at':int(time.time()),'sample_id':sample_id}
                        except (OSError,ValueError,UnicodeError):metrics=None
                        next_sample=time.monotonic()+1
                    atomic(STATE/'status.json',{'version':1,'updated':int(time.time()),'revision':revision,'running':True,'profiles':len(active),'host':public,'port':8443,'metrics':metrics})
            time.sleep(.25)
    except KeyboardInterrupt:pass
    finally:
        stop(process)
        if log:log.close()
        atomic(STATE/'status.json',{'version':1,'updated':int(time.time()),'running':False})


if __name__=='__main__':main()
