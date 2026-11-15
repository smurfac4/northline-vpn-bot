"""Manage only the dedicated Telegram MTProxy test container and its TCP port."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parent.parent
STATE=ROOT/'data/mtproxy'
NAME='northline-tg-test'
LABEL='org.northline.mtproxy-test'


def run(*args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30,**kwargs).stdout.strip()


def router():
    spec=importlib.util.spec_from_file_location('pc_router',ROOT/'deploy/pc-test.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    result=module.Router();result.port=8443;result.protocol='TCP';result.description='Northline Telegram test';result.record_path=STATE/'network.json'
    return result


def owned():
    result=subprocess.run(['docker','inspect',NAME],capture_output=True,text=True,timeout=5)
    if result.returncode:return None
    data=json.loads(result.stdout)[0]
    if data['Config']['Labels'].get(LABEL)!='1':raise RuntimeError('Container name belongs to another project')
    return data


def start():
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True);STATE.chmod(0o700)
    with urlopen('https://api.ipify.org',timeout=5) as response:public=response.read(80).decode().strip()
    public=str(ipaddress.IPv4Address(public))
    (STATE/'public-ip').write_text(public+'\n')
    info=owned()
    if not info or not info['State']['Running']:
        (STATE/'status.json').unlink(missing_ok=True)
    if info:
        if not info['State']['Running']:run('docker','start',NAME)
    else:
        run('docker','run','-d','--name',NAME,'--label',LABEL+'=1','--network','bridge',
            '--restart','unless-stopped','--cap-drop','ALL','--memory','256m','--cpus','1','--pids-limit','64',
            '-p','0.0.0.0:8443:8443/tcp','--mount','type=bind,src='+str(STATE)+',dst=/state','northline-mtproxy:local')
    entrypoint=ROOT/'deploy/mtproxy/entrypoint.py'
    expected=hashlib.sha256(entrypoint.read_bytes()).hexdigest()
    installed=run('docker','exec',NAME,'python3','-c',"import hashlib; print(hashlib.sha256(open('/app/entrypoint.py','rb').read()).hexdigest())")
    if installed!=expected:
        run('docker','cp',str(entrypoint),NAME+':/app/entrypoint.py')
        (STATE/'status.json').unlink(missing_ok=True)
        run('docker','restart',NAME)
    for _ in range(100):
        try:
            data=json.loads((STATE/'status.json').read_text())
            if data.get('running') and 0<=time.time()-data['updated']<3:
                print('Telegram MTProto proxy is running on TCP 8443.');return
        except (OSError,ValueError,KeyError):pass
        time.sleep(.2)
    raise RuntimeError('MTProxy did not start; inspect the private process log in data/mtproxy')


def probe(secret=None):
    network=json.loads((STATE/'network.json').read_text())
    if secret is None:
        rows=json.loads((STATE/'desired.json').read_text())['profiles']
        active=[row for row in rows if row['expires']==0 or row['expires']>time.time()]
        if not active:raise RuntimeError('Create an active Telegram profile first')
        secret=active[0]['secret']
    payload={'host':network['public_ip'],'port':8443,'secret':secret}
    code=(ROOT/'deploy/mtproxy/probe.py').read_text()
    name='northline-mtproxy-probe-'+secrets.token_hex(4)
    try:
        result=run('docker','run','--rm','-i','--name',name,'--label','org.northline.mtproxy-probe=1',
            '--network','bridge','--cap-drop','ALL','--memory','128m','--entrypoint','python3','northline-mtproxy:local','-c',code,input=json.dumps(payload))
        print('End-to-end Telegram proxy probe:',result);return json.loads(result)
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
        raise RuntimeError('Telegram did not return a valid MTProto response through this proxy') from None
    finally:
        subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=10)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('start','map','probe','status','stop'))
    action=parser.parse_args().action;os.umask(0o077)
    if action=='start':start()
    elif action=='map':router().add()
    elif action=='probe':probe()
    elif action=='status':
        info=owned();print('Container:',info['State']['Status'] if info else 'not created')
        if (STATE/'status.json').exists():print((STATE/'status.json').read_text())
    elif action=='stop':
        try:router().remove()
        finally:
            if owned():run('docker','stop',NAME)


if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError) as error:sys.exit(str(error))
