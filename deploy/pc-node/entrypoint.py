"""WireGuard test node inside its own Docker network namespace."""
import ipaddress
import os
from pathlib import Path
import signal
import subprocess
import time

STATE=Path('/var/lib/northline-wg')


def command(*args,**kwargs):
    return subprocess.run(args,check=True,timeout=15,**kwargs)


def main():
    os.umask(0o077);STATE.mkdir(parents=True,exist_ok=True)
    subnet=ipaddress.IPv4Network((STATE/'subnet').read_text().strip())
    if subnet.prefixlen!=24 or not subnet.is_private:raise ValueError('Use a private /24 subnet')
    key=STATE/'server.key'
    if not key.exists():
        with key.open('w') as stream:command('wg','genkey',stdout=stream)
    public=command('wg','pubkey',input=key.read_text(),text=True,capture_output=True).stdout.strip()
    (STATE/'server.pub').write_text(public+'\n')
    processes=[]
    try:
        result=subprocess.run(['ip','link','add','wg0','type','wireguard'],capture_output=True)
        if result.returncode:
            processes.append(subprocess.Popen(['wireguard-go','-f','wg0']))
            for _ in range(30):
                if subprocess.run(['ip','link','show','wg0'],capture_output=True).returncode==0:break
                time.sleep(.1)
            else:raise RuntimeError('WireGuard interface did not start')
        command('ip','address','add',str(subnet.network_address+1)+'/24','dev','wg0')
        command('wg','set','wg0','listen-port','51820','private-key',str(key))
        command('ip','link','set','wg0','mtu','1380','up')
        route=command('ip','-4','route','show','default',text=True,capture_output=True).stdout.split()
        nic=route[route.index('dev')+1]
        command('iptables','-P','FORWARD','DROP')
        command('iptables','-A','INPUT','-i','wg0','-j','DROP')
        command('iptables','-A','FORWARD','-i',nic,'-o','wg0','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
        for network in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16'):
            command('iptables','-A','FORWARD','-i','wg0','-d',network,'-j','DROP')
        command('iptables','-A','FORWARD','-i','wg0','-o',nic,'-s',str(subnet),'-j','ACCEPT')
        command('iptables','-t','nat','-A','POSTROUTING','-s',str(subnet),'-o',nic,'-j','MASQUERADE')
        pub=(STATE/'controller.pub').read_text().strip()
        if not pub.startswith('ssh-ed25519 ') or '\n' in pub:raise ValueError('Invalid controller public key')
        Path('/root/.ssh/authorized_keys').write_text('restrict,command="/app/ssh-control.sh" '+pub+'\n')
        host_key=STATE/'ssh_host_ed25519_key'
        if not host_key.exists():command('ssh-keygen','-q','-t','ed25519','-N','','-f',str(host_key))
        ssh_config=Path('/run/sshd-northline.conf')
        ssh_config.write_text('Port 22\nHostKey '+str(host_key)+'\nPermitRootLogin prohibit-password\n'
            'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
            'AllowUsers root\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\n'
            'AuthorizedKeysFile /root/.ssh/authorized_keys\nPrintMotd no\nLogLevel ERROR\n')
        command('python3','/app/node_control.py','sync')
        processes.append(subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(ssh_config)]))
        def stop(*_):raise KeyboardInterrupt
        signal.signal(signal.SIGTERM,stop)
        print('Northline PC node ready: UDP 51820; restricted SSH.',flush=True)
        next_sync=time.monotonic()+20
        while all(process.poll() is None for process in processes):
            if time.monotonic()>=next_sync:
                command('python3','/app/node_control.py','sync');next_sync=time.monotonic()+20
            time.sleep(1)
        raise RuntimeError('A node process exited')
    except KeyboardInterrupt:pass
    finally:
        for process in processes:
            if process.poll() is None:process.terminate()
        for process in processes:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':main()
