"""Start/stop the dedicated Docker WireGuard test node on this Mac."""
import argparse
import json
import os
import secrets
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import urljoin,urlsplit
from urllib.request import Request,urlopen
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parent.parent
STATE=ROOT/'data/pc-test'
NAME='northline-local-node'
LABEL='org.northline.pc-test'
PORT=51820


def run(*args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30,**kwargs).stdout.strip()


def identity():
    route=run('route','-n','get','default').splitlines()
    values=dict(line.strip().split(':',1) for line in route if ':' in line)
    interface=values['interface'].strip();gateway=values['gateway'].strip()
    address=run('ipconfig','getifaddr',interface)
    return address,gateway


def owned_container():
    result=subprocess.run(['docker','inspect',NAME],capture_output=True,text=True,timeout=10)
    if result.returncode:return None
    info=json.loads(result.stdout)[0]
    if info['Config']['Labels'].get(LABEL)!='1':raise RuntimeError('Container name belongs to another project')
    return info


def start():
    STATE.mkdir(parents=True,exist_ok=True);STATE.chmod(0o700)
    if not (STATE/'controller').exists():run('ssh-keygen','-q','-t','ed25519','-N','','-f',str(STATE/'controller'))
    subnet=STATE/'subnet'
    if subnet.exists() and subnet.read_text().strip()!='10.253.77.0/24':raise RuntimeError('Preserve the existing node subnet')
    subnet.write_text('10.253.77.0/24\n')
    existing=owned_container()
    if existing:
        if not existing['State']['Running']:run('docker','start',NAME)
    else:
        run('docker','run','-d','--name',NAME,'--label',LABEL+'=1','--restart','unless-stopped',
            '--cap-add','NET_ADMIN','--device','/dev/net/tun','--sysctl','net.ipv4.ip_forward=1',
            '--memory','256m','--pids-limit','128','-p','0.0.0.0:51820:51820/udp','-p','127.0.0.1:22222:22/tcp',
            '--mount','type=bind,src='+str(STATE)+',dst=/var/lib/northline-wg','northline-pc-node:local')
    run('docker','cp',str(ROOT/'deploy/node_control.py'),NAME+':/app/node_control.py')
    for _ in range(50):
        check=subprocess.run(['docker','exec',NAME,'wg','show','wg0','public-key'],capture_output=True,text=True,timeout=3)
        if check.returncode==0 and check.stdout.strip() and (STATE/'ssh_host_ed25519_key.pub').exists():break
        time.sleep(.2)
    else:raise RuntimeError('Node did not start; inspect docker logs northline-local-node')
    host_key=' '.join((STATE/'ssh_host_ed25519_key.pub').read_text().split()[:2])
    (STATE/'known_hosts').write_text('[127.0.0.1]:22222 '+host_key+'\n')
    (STATE/'ssh.config').write_text('Host northline-local-node\n  HostName 127.0.0.1\n  Port 22222\n  User root\n'
        '  IdentityFile "'+str(STATE/'controller')+'"\n  IdentitiesOnly yes\n  UserKnownHostsFile "'+str(STATE/'known_hosts')+'"\n'
        '  StrictHostKeyChecking yes\n  BatchMode yes\n')
    tools=ROOT/'data/tools';tools.mkdir(exist_ok=True)
    wrapper=tools/'wg-pc-test'
    docker=shutil.which('docker')
    if not docker:raise RuntimeError('Docker CLI is required')
    wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(docker)+' exec -i '+NAME+' wg "$@"\n');wrapper.chmod(0o700)
    for _ in range(30):
        result=subprocess.run(['ssh','-F',str(STATE/'ssh.config'),'northline-local-node','ping'],capture_output=True,text=True,timeout=3)
        if result.returncode==0:
            if result.stdout.strip()!=check.stdout.strip():raise RuntimeError('SSH returned a different WireGuard public key')
            print('PC WireGuard node ready; restricted SSH verified.');return
        time.sleep(.2)
    raise RuntimeError('Restricted SSH is not ready')


def probe():
    """Check a real handshake without modifying any default route or DNS."""
    if not owned_container() or not owned_container()['State']['Running']:raise RuntimeError('Start the PC node first')
    network=json.loads((STATE/'network.json').read_text())
    wrapper=str(ROOT/'data/tools/wg-pc-test')
    private=run(wrapper,'genkey');public=run(wrapper,'pubkey',input=private+'\n')
    server=run('ssh','-F',str(STATE/'ssh.config'),NAME,'ping')
    peers=json.loads((STATE/'peers.json').read_text()) if (STATE/'peers.json').exists() else {}
    if any(peer['address']=='10.253.77.254/32' for peer in peers.values()):raise RuntimeError('Probe address is already in use')
    name='northline-pc-probe-'+secrets.token_hex(4);created=False;added=False
    try:
        run('ssh','-F',str(STATE/'ssh.config'),NAME,'add',public,'10.253.77.254/32',str(int(time.time())+120));added=True
        code=(ROOT/'deploy/pc-node/probe.py').read_text()
        run('docker','create','-i','--name',name,'--label','org.northline.pc-probe=1','--network','bridge',
            '--cap-add','NET_ADMIN','--entrypoint','python3','northline-pc-node:local','-c',code);created=True
        mode=run('docker','inspect',name,'--format','{{.HostConfig.NetworkMode}}')
        if mode!='bridge':raise RuntimeError('Probe requires its own bridge-network namespace')
        result=run('docker','start','-a','-i',name,input=json.dumps({'private':private,'server':server,'endpoint':network['public_ip'],'address':'10.253.77.254/32'}))
        data=json.loads(result)
        if data['egress_ip']!=network['public_ip']:raise RuntimeError('Unexpected VPN egress address')
        (STATE/'probe.json').write_text(json.dumps({**data,'tested_at':int(time.time()),'path':'public-ip-router-hairpin','probe_route':'1.0.0.1/32'},indent=2)+'\n')
        print('Real WireGuard handshake and HTTPS traffic verified:',json.dumps(data))
    finally:
        try:
            if created:run('docker','rm','-f',name)
        finally:
            if added:run('ssh','-F',str(STATE/'ssh.config'),NAME,'remove',public)


class Router:
    port=PORT
    protocol='UDP'
    description='Northline PC test'
    record_path=None
    def __init__(self):
        self.address,self.gateway=identity()
        message=('M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n').encode()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
            connection.settimeout(3);connection.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,2)
            connection.sendto(message,('239.255.255.250',1900))
            while True:
                reply,source=connection.recvfrom(8192)
                if source[0]!=self.gateway:continue
                fields=dict(line.split(':',1) for line in reply.decode(errors='replace').split('\r\n')[1:] if ':' in line)
                location=next(value.strip() for key,value in fields.items() if key.lower()=='location')
                if urlsplit(location).hostname!=self.gateway:continue
                break
        with urlopen(location,timeout=4) as response:root=ET.fromstring(response.read())
        ns={'u':'urn:schemas-upnp-org:device-1-0'}
        for service in root.findall('.//u:service',ns):
            kind=service.findtext('u:serviceType','',ns)
            if 'WANIPConnection' in kind or 'WANPPPConnection' in kind:
                self.kind=kind;self.control=urljoin(location,service.findtext('u:controlURL','',ns));break
        else:raise RuntimeError('Router does not expose a WAN control service')
        if urlsplit(self.control).hostname!=self.gateway:raise RuntimeError('Unexpected router control address')

    def call(self,action,values=None):
        body=ET.Element('{http://schemas.xmlsoap.org/soap/envelope/}Envelope')
        content=ET.SubElement(body,'{http://schemas.xmlsoap.org/soap/envelope/}Body')
        operation=ET.SubElement(content,'{'+self.kind+'}'+action)
        for key,value in (values or {}).items():ET.SubElement(operation,key).text=str(value)
        request=Request(self.control,data=ET.tostring(body,encoding='utf-8',xml_declaration=True),
            headers={'Content-Type':'text/xml; charset="utf-8"','SOAPAction':'"'+self.kind+'#'+action+'"'})
        try:
            with urlopen(request,timeout=5) as response:root=ET.fromstring(response.read())
        except HTTPError as error:
            root=ET.fromstring(error.read());code=next((node.text for node in root.iter() if node.tag.endswith('errorCode')),str(error.code))
            if action=='GetSpecificPortMappingEntry' and code=='714':return None
            raise RuntimeError('Router rejected '+action+' (UPnP '+str(code)+')') from None
        return {node.tag.rsplit('}',1)[-1]:node.text for node in root.iter() if len(node)==0}

    def mapping(self):
        return self.call('GetSpecificPortMappingEntry',{'NewRemoteHost':'','NewExternalPort':self.port,'NewProtocol':self.protocol})

    def require_ours(self,entry):
        if entry and (entry.get('NewInternalClient')!=self.address or entry.get('NewInternalPort')!=str(self.port)
                      or entry.get('NewPortMappingDescription')!=self.description):
            raise RuntimeError('Requested port already belongs to another device/application; no settings changed')

    def add(self):
        entry=self.mapping();self.require_ours(entry)
        external=self.call('GetExternalIPAddress')['NewExternalIPAddress']
        with urlopen('https://api.ipify.org',timeout=5) as response:public=response.read(80).decode().strip()
        if external!=public:raise RuntimeError('Router WAN address differs from public IP; check upstream NAT first')
        self.call('AddPortMapping',{'NewRemoteHost':'','NewExternalPort':self.port,'NewProtocol':self.protocol,
            'NewInternalPort':self.port,'NewInternalClient':self.address,'NewEnabled':1,
            'NewPortMappingDescription':self.description,'NewLeaseDuration':3600})
        current=self.mapping();self.require_ours(current)
        if not current:raise RuntimeError('Router did not retain the requested mapping')
        state={'public_ip':public,'local_ip':self.address,'gateway':self.gateway,'port':self.port,'protocol':self.protocol,'mapped_at':int(time.time()),'lease_seconds':3600}
        (self.record_path or STATE/'network.json').write_text(json.dumps(state,indent=2)+'\n')
        print('One-hour '+self.protocol+' mapping verified:',public+':'+str(self.port),'->',self.address+':'+str(self.port))

    def remove(self):
        entry=self.mapping();self.require_ours(entry)
        if entry:self.call('DeletePortMapping',{'NewRemoteHost':'','NewExternalPort':self.port,'NewProtocol':self.protocol})
        print('Northline test port mapping removed.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('start','map','probe','status','stop'))
    args=parser.parse_args();os.umask(0o077)
    if args.action=='start':start()
    elif args.action=='map':Router().add()
    elif args.action=='probe':probe()
    elif args.action=='status':
        info=owned_container();print('Container:',info['State']['Status'] if info else 'not created')
        if info and info['State']['Running']:print(run('ssh','-F',str(STATE/'ssh.config'),NAME,'metrics'))
        print('Router mapping:',json.dumps(Router().mapping()))
    elif args.action=='stop':
        try:Router().remove()
        finally:
            if owned_container():run('docker','stop',NAME)


if __name__=='__main__':main()
