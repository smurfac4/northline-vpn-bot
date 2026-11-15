"""Start the local local independently of a terminal; optionally renew its HTTPS tunnel."""
import argparse
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit

ROOT=Path(__file__).resolve().parent.parent
DATA=ROOT/'data'


def atomic_write(path, content):
    temporary=path.with_name('.'+path.name+'.'+secrets.token_hex(6))
    try:
        fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(content);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()


def stop_process(process, group=False):
    if process is None:return
    if group:
        # Only used with a Popen child created here with start_new_session=True.
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
    elif process.poll() is None:
        try:process.terminate()
        except ProcessLookupError:pass
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if group:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        else:process.kill()
        process.wait(timeout=3)
    if group:
        # A dead group leader can still leave its backend holding the port.
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass


def healthy_url(url, timeout=3):
    try:
        with urlopen(url+'/health',timeout=timeout) as response:
            result=json.load(response)
        return isinstance(result,dict) and result.get('ok') is True and result.get('service')=='northline'
    except URLError as error:
        # Some local resolvers cache NXDOMAIN for newly allocated Quick Tunnels.
        # Resolve only those local hosts via DoH; TLS still checks the original host.
        parsed=urlsplit(url)
        if not isinstance(error.reason,socket.gaierror) or parsed.scheme!='https' or not (parsed.hostname or '').endswith('.trycloudflare.com'):
            return False
        return healthy_local_dns(parsed,timeout)
    except (OSError,ValueError,TypeError):return False


def healthy_local_dns(parsed,timeout):
    try:
        query=urlencode({'name':parsed.hostname,'type':'A'})
        request=Request('https://cloudflare-dns.com/dns-query?'+query,headers={'Accept':'application/dns-json'})
        with urlopen(request,timeout=timeout) as response:
            records=json.load(response)
        if not isinstance(records,dict) or records.get('Status')!=0:return False
        for record in records.get('Answer',[]):
            if not isinstance(record,dict) or record.get('type')!=1:continue
            address=str(ipaddress.IPv4Address(record['data']))
            if not ipaddress.ip_address(address).is_global:continue
            connection=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,timeout=timeout)
            connection._create_connection=lambda target,timeout,source_address=None:socket.create_connection((address,target[1]),timeout,source_address)
            try:
                connection.request('GET',(parsed.path.rstrip('/') or '')+'/health')
                response=connection.getresponse()
                if response.status!=200:continue
                result=json.load(response)
                if isinstance(result,dict) and result.get('ok') is True and result.get('service')=='northline':return True
            except (OSError,ValueError,http.client.HTTPException):pass
            finally:connection.close()
    except (OSError,ValueError,TypeError,KeyError,http.client.HTTPException):pass
    return False


def tunnel_registration_lost():
    try:
        with (DATA/'cloudflared.log').open('rb') as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell()-8192))
            tail=stream.read()
        return tail.rfind(b'Unauthorized: Tunnel not found') > tail.rfind(b'Registered tunnel connection')
    except OSError:
        return False


def monitor(app, tunnel, public_url, restart_app=None, local_url=None):
    failures=0;next_check=time.monotonic()+30
    while True:
        if tunnel and tunnel.poll() is not None:
            raise RuntimeError('A managed process stopped (HTTPS tunnel); restarting the local service.')
        if app.poll() is not None:
            if restart_app is None:raise RuntimeError('A managed process stopped (application).')
            app=restart_app()
        if time.monotonic()>=next_check:
            failures=0 if healthy_url(public_url) else failures+1
            if failures>=3:
                if local_url and not healthy_url(local_url) and restart_app:
                    print('Local application is unavailable; recovering it without changing the HTTPS address.',flush=True)
                    app=restart_app()
                else:
                    if tunnel and tunnel_registration_lost():
                        raise RuntimeError('HTTPS tunnel registration was lost; creating a new public address.')
                    print('Public HTTPS check failed; preserving the running tunnel while it reconnects.',flush=True)
                failures=0
            next_check=time.monotonic()+30
        time.sleep(1)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--tunnel',action='store_true',help='Start a Cloudflare local tunnel and update PUBLIC_URL')
    parser.add_argument('--monitor',action='store_true',help='Remain running and fail when the application or tunnel becomes unavailable')
    parser.add_argument('--background',action='store_true',help='Start a detached supervisor that recovers the application and tunnel')
    parser.add_argument('--protocol',choices=('http2','quic','auto'),default='http2')
    args=parser.parse_args()
    os.umask(0o077)
    if args.background:
        DATA.mkdir(exist_ok=True)
        with (DATA/'launcher.log').open('a') as log:
            child=subprocess.Popen([sys.executable,'-u',str(Path(__file__).resolve()),
                *[argument for argument in sys.argv[1:] if argument not in ('--background','--monitor')],'--monitor'],
                cwd=ROOT,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        for _ in range(120):
            if child.poll() is not None:raise SystemExit('The supervisor stopped. See data/launcher.log.')
            try:
                state=json.loads((DATA/'local-processes.json').read_text())
                if state.get('supervisor_pid')==child.pid:
                    print('Supervised application started. Logs: data/launcher.log');return
            except (OSError,ValueError,TypeError):pass
            time.sleep(1)
        stop_process(child)
        raise SystemExit('Startup did not finish. See data/launcher.log.')
    def stop(_signum,_frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    os.umask(0o077);DATA.mkdir(exist_ok=True)
    with (DATA/'local-start.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        env_path=ROOT/'.env'
        previous_env=env_path.read_bytes() if env_path.exists() else None
        lines=previous_env.decode().splitlines() if previous_env is not None else []
        written_env=None
        values=dict(line.strip().split('=',1) for line in lines if '=' in line and not line.lstrip().startswith('#'))
        for key in ('PORT','PUBLIC_URL'):
            if key in os.environ:values[key]=os.environ[key]
        try:port=int(values.get('PORT','8000'))
        except ValueError:raise SystemExit('PORT must be an integer from 1 to 65535.')
        if not 1<=port<=65535:raise SystemExit('PORT must be between 1 and 65535.')
        with socket.socket() as check:
            if check.connect_ex(('127.0.0.1',port))==0:
                raise SystemExit(f'Port {port} is already in use. Stop the existing project before starting a background copy.')
        tunnel=None;app=None;started=False
        try:
            if args.tunnel:
                if os.environ.get('PUBLIC_URL'):raise SystemExit('PUBLIC_URL is fixed by the launch environment. Remove the override before creating a temporary tunnel.')
                allowed=values.get('ALLOWED_TELEGRAM_IDS','').strip()
                admins={item.strip() for item in values.get('ADMIN_TELEGRAM_IDS','').split(',') if item.strip()}
                personal=values.get('PERSONAL_TEST')=='1' and allowed.isascii() and allowed.isdigit() and 0<int(allowed)<2**63 and allowed in admins
                if not personal:
                    raise SystemExit('Temporary tunnels require an explicit personal test restricted to one administrator.')
                executable=shutil.which('cloudflared')
                if not executable:
                    binary=DATA/'tools'/'cloudflared'
                    if not binary.exists() and Path('/tmp/cloudflared').exists():
                        binary.parent.mkdir(exist_ok=True);shutil.copy2('/tmp/cloudflared',binary);binary.chmod(0o700)
                    executable=str(binary) if binary.exists() else None
                if not executable:raise SystemExit('Install cloudflared first.')
                log_path=DATA/'cloudflared.log'
                with log_path.open('w') as log:
                    tunnel=subprocess.Popen([executable,'tunnel','--url',f'http://127.0.0.1:{port}','--no-autoupdate','--protocol',args.protocol,'--grace-period','2s'],
                        stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                url=None
                for _ in range(60):
                    match=re.search(r'https://[a-z0-9-]+\.trycloudflare\.com',log_path.read_text())
                    if match:url=match[0];break
                    if tunnel.poll() is not None:raise RuntimeError('Tunnel stopped. See data/cloudflared.log.')
                    time.sleep(.5)
                if not url:raise RuntimeError('Tunnel URL was not received. See data/cloudflared.log.')
                lines=[line for line in lines if not line.strip().startswith('PUBLIC_URL=')]
                lines.append('PUBLIC_URL='+url)
                written_env=('\n'.join(lines)+'\n').encode()
                atomic_write(env_path,written_env)
                values['PUBLIC_URL']=url
            def launch_app():
                with (DATA/'application.log').open('a') as log:
                    app_env=dict(os.environ)
                    if args.monitor:app_env['NORTHLINE_MANAGED']='1'
                    return subprocess.Popen([sys.executable,str(ROOT/'run.py')],cwd=ROOT,
                        env=app_env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            app=launch_app()
            healthy=False
            for _ in range(30):
                if app.poll() is not None:raise RuntimeError('Application stopped. See data/application.log.')
                try:
                    with urlopen(f'http://127.0.0.1:{port}/health',timeout=.5) as response:
                        health=json.load(response)
                        healthy=health.get('ok') is True and health.get('service')=='northline'
                    if healthy:break
                except (OSError,ValueError,TypeError):pass
                time.sleep(.2)
            if not healthy:raise RuntimeError('Application did not become ready. See data/application.log.')
            if args.tunnel:
                reachable=False
                deadline=time.monotonic()+65
                while time.monotonic()<deadline:
                    if app.poll() is not None or tunnel.poll() is not None:break
                    reachable=healthy_url(values['PUBLIC_URL'])
                    if reachable:break
                    time.sleep(2)
                if not reachable:raise RuntimeError('The HTTPS tunnel did not reach Northline. See data/cloudflared.log.')
            def save_pids():
                atomic_write(DATA/'local-processes.json',json.dumps({'supervisor_pid':os.getpid() if args.monitor else None,'app_pid':app.pid,'tunnel_pid':tunnel.pid if tunnel else None}).encode())
            save_pids()
            started=True
            print('Background application started. Logs: data/application.log',flush=True)
            print('Mini App: '+values.get('PUBLIC_URL',f'http://127.0.0.1:{port}'),flush=True)
            def restart_app():
                nonlocal app
                stop_process(app,group=True)
                app=launch_app()
                for _ in range(40):
                    if app.poll() is not None:raise RuntimeError('Application recovery failed. See data/application.log.')
                    if healthy_url(f'http://127.0.0.1:{port}',timeout=.5):
                        save_pids();return app
                    time.sleep(.25)
                raise RuntimeError('Application did not recover. See data/application.log.')
            if args.monitor:monitor(app,tunnel,values.get('PUBLIC_URL') or f'http://127.0.0.1:{port}',restart_app,f'http://127.0.0.1:{port}')
        except BaseException:
            for process in (app,tunnel):stop_process(process,group=args.monitor)
            if not started and written_env is not None:
                try:
                    if env_path.exists() and env_path.read_bytes()==written_env:
                        if previous_env is None:env_path.unlink()
                        else:atomic_write(env_path,previous_env)
                except OSError:
                    print('Could not restore PUBLIC_URL after startup failure. Check .env locally.',file=sys.stderr)
            raise


if __name__=='__main__':
    while True:
        try:main();break
        except KeyboardInterrupt:break
        except Exception as error:
            if '--monitor' not in sys.argv:raise
            print(str(error),file=sys.stderr,flush=True)
            print('Retrying the local service in 10 seconds.',file=sys.stderr,flush=True)
            try:time.sleep(10)
            except KeyboardInterrupt:break
