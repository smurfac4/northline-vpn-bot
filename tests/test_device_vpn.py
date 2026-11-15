from support import install_test_catalogs
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import settings
from backend import device_vpn, device_refresh
from backend.admin import Admin
from backend.registry import Registry
from backend.service import VPN, Problem


def raw_config(address='8.8.8.8'):
    text = 'client\ndev tun\nproto tcp\nremote '+address+' 443\ncipher AES-128-CBC\nauth SHA1\n'
    for kind in ('ca','cert','key'):
        label = 'PRIVATE KEY' if kind == 'key' else 'CERTIFICATE'
        text += '<'+kind+'>\n-----BEGIN '+label+'-----\nQUJD\n-----END '+label+'-----\n</'+kind+'>\n'
    return text


def node_row(address='8.8.8.8', code='US'):
    config, endpoint = device_vpn.sanitize_config(raw_config(address))
    return {'id':'ovpn-'+code.lower()+'-'+hashlib.sha256(config.encode()).hexdigest()[:12],
            'name':code,'country':code,'country_name':code,'endpoint':endpoint,'config':config,
            'checked_at':int(time.time()),'latency_ms':100,'egress_ip':address}


class DeviceConfigTests(unittest.TestCase):
    def test_safe_config_is_canonical_and_requires_server_certificate_validation(self):
        config, endpoint = device_vpn.sanitize_config(raw_config())
        self.assertEqual(endpoint, '8.8.8.8:443')
        self.assertIn('remote-cert-tls server\ntls-version-min 1.2\n', config)
        self.assertIn('redirect-gateway def1\n', config)
        self.assertEqual(device_vpn.sanitize_config(config)[0], config)

    def test_untrusted_config_cannot_run_scripts_plugins_or_read_local_files(self):
        for directive in ('script-security 2','up /tmp/run','plugin /tmp/plugin.so','management 127.0.0.1 9000',
                          'ca /etc/private','auth-user-pass /etc/secret','remote 1.1.1.1 443','tls-version-min 1.0'):
            with self.subTest(directive=directive), self.assertRaises(ValueError):
                device_vpn.sanitize_config(raw_config()+directive+'\n')
        for address in ('127.0.0.1','10.0.0.1','192.168.0.1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                device_vpn.sanitize_config(raw_config(address))

    def test_official_csv_supplies_a_complete_openvpn_profile(self):
        output=io.StringIO();writer=csv.writer(output)
        writer.writerow(['#HostName','IP','Speed','Ping','CountryLong','CountryShort','OpenVPN_ConfigData_Base64'])
        writer.writerow(['host','8.8.8.8','10000000','20','United States','US',base64.b64encode(raw_config().encode()).decode()])
        rows=device_vpn.parse_source('*vpn_servers\n'+output.getvalue()+'*\n')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['country'],'US')
        self.assertTrue(device_vpn.public(next(iter(device_vpn.parse_nodes(rows).values()))))
        self.assertNotIn('PRIVATE KEY',repr(next(iter(device_vpn.parse_nodes(rows).values()))))

    def test_stored_config_cannot_be_changed_without_validation(self):
        row=node_row();row['config']+='up /tmp/execute\n'
        row['id']='ovpn-us-'+hashlib.sha256(row['config'].encode()).hexdigest()[:12]
        with self.assertRaises(ValueError):device_vpn.parse_nodes([row])

    def test_connection_probe_uses_only_an_isolated_ephemeral_container(self):
        node=device_vpn.parse_nodes([node_row()])[node_row()['id']]
        result=Mock(stdout=json.dumps({'tunnel_established':True,'egress_ip':'1.1.1.1','latency_ms':123}))
        with patch.object(device_vpn.subprocess,'run',return_value=result) as run:
            self.assertEqual(device_vpn.check(node)['latency_ms'],123)
        command=run.call_args_list[0].args[0]
        self.assertEqual(command[command.index('--network')+1],'bridge')
        self.assertNotIn('--privileged',command)
        self.assertNotIn(node.config,' '.join(command))
        self.assertEqual(json.loads(run.call_args_list[0].kwargs['input'])['config'],node.config)
        self.assertEqual(run.call_args_list[-1].args[0][1:3],['rm','-f'])

    def test_russian_source_accepts_only_its_published_ip_configs(self):
        parser=device_vpn.RussianConfigLinks()
        parser.feed('<a href="https://vpnobratno.info/servers/vpn123.opengw.net/vpn123.opengw.net_ip_udp.ovpn">UDP</a>'
                    '<a href="https://vpnobratno.info/servers/vpn123.opengw.net/vpn123.opengw.net_ip_tcp.ovpn">TCP</a>'
                    '<a href="https://evil.example/servers/vpn123.opengw.net/vpn123.opengw.net_ip_udp.ovpn">Foreign</a>'
                    '<a href="https://vpnobratno.info/servers/vpn123.opengw.net/vpn456.opengw.net_ip_udp.ovpn">Mismatched</a>'
                    '<a href="https://vpnobratno.info/servers/vpn123.opengw.net/vpn123.opengw.net_ddns_udp.ovpn">DNS</a>')
        self.assertEqual(len(parser.links),2)
        self.assertTrue(all('_ip_' in link for link in parser.links))


class DeviceProfileTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        config=patch.multiple(settings,MODE='live',ROOT=self.root,DB=self.root/'vpn.sqlite3',
                              DEVICE_NODES=self.root/'device-vpn.json',PROXY_NODES=self.root/'telegram.json',
                              NODES=self.root/'owned.json',ALLOW='*',ADMIN_IDS='10',TOKEN='test',BOT_KEY='internal',
                              PUBLIC_URL='https://app.example.com')
        config.start();self.addCleanup(config.stop)
        runtime=patch.object(device_refresh,'require_probe');runtime.start();self.addCleanup(runtime.stop)
        self.vpn=VPN();self.telegram=self.vpn.issue(10,'tg-eu',scope='telegram')
        live=patch.object(settings,'MODE','live');live.start();self.addCleanup(live.stop)
        self.row=node_row();self.node=device_vpn.parse_nodes([self.row])[self.row['id']]
        self.vpn.catalogs['device']={**self.vpn.nodes,self.node.id:self.node}
        settings.DEVICE_NODES.write_text(json.dumps([self.row]))
        settings.PROXY_NODES.write_text('[]\n')

    def test_public_device_profile_never_creates_a_wireguard_peer_or_mtproto_secret(self):
        with patch('backend.wireguard.keys') as keys,patch('backend.wireguard.control') as control,patch('backend.proxy.sync') as sync:
            profile=self.vpn.issue(10,self.node.id)
            connection=self.vpn.connection(10,'device','ios')
            self.vpn.issue(11,self.node.id)
        keys.assert_not_called();control.assert_not_called();sync.assert_not_called()
        self.assertEqual(profile['protocol'],'OpenVPN')
        self.assertEqual(profile['access_type'],'public')
        self.assertEqual(connection['download']['filename'],'northline-vpn.ovpn')
        self.assertEqual(connection['download']['content'],self.node.config)
        self.assertEqual(connection['client']['name'],'OpenVPN Connect')
        self.assertTrue(connection['client']['native_import'])
        self.assertTrue(connection['client']['external_import'])
        self.assertEqual(connection['import_page_url'].replace('/connect-import/','/connect-config/',1),connection['download_url'])
        filename,content=self.vpn.import_file(connection['download_url'].rsplit('/',1)[1])
        self.assertEqual(filename,'northline-vpn.ovpn');self.assertEqual(content,self.node.config)
        self.assertIn('OpenVPN Connect',connection['steps'][0])
        self.assertIn('журналы',connection['notice'])
        self.assertEqual(self.vpn.status(10,'telegram'),self.telegram)
        self.assertNotIn('PRIVATE KEY',json.dumps(self.vpn.visible_nodes('device')))

    def test_revoke_public_vpn_does_not_touch_telegram_or_call_ssh(self):
        self.vpn.issue(10,self.node.id)
        with patch('backend.wireguard.control') as control,patch('backend.proxy.sync') as sync:
            self.vpn.revoke(10)
        control.assert_not_called();sync.assert_not_called()
        self.assertEqual(self.vpn.status(10,'telegram'),self.telegram)
        self.assertEqual(self.vpn.current(10)['private_key'],'')

    def test_device_nodes_cannot_be_used_in_telegram_mode(self):
        with self.assertRaises(Problem):self.vpn.issue(10,self.node.id,scope='telegram')
        with self.assertRaises(Problem):self.vpn.issue(10,'tg-eu',scope='device')

    def test_stale_public_vpn_cannot_issue_a_new_profile(self):
        row={**self.row,'checked_at':0}
        self.vpn.catalogs['device'][self.node.id]=device_vpn.parse_nodes([row])[self.node.id]
        with self.assertRaises(Problem):self.vpn.issue(10,self.node.id)
        self.assertTrue(next(row for row in self.vpn.visible_nodes('device') if row['id']==self.node.id)['maintenance'])

    def test_refresh_replaces_only_the_public_device_registry_and_keeps_active_profiles(self):
        old=self.vpn.issue(10,self.node.id)
        original,revision=device_refresh.read_registry()
        replacement=node_row('1.1.1.1')
        telegram_file=settings.PROXY_NODES.read_bytes()
        device_refresh.apply(self.vpn,original,revision,{'US':replacement})
        self.assertTrue(self.vpn.catalogs['device'][self.node.id].retired)
        self.assertEqual(self.vpn.status(10)['id'],old['id'])
        with self.assertRaises(Problem):self.vpn.config(10)
        self.assertTrue(self.vpn.status(10)['node_retired'])
        self.assertEqual(self.vpn.current(10)['private_key'],self.node.config)
        self.assertIn('wg-eu',self.vpn.catalogs['device'])
        self.assertEqual(settings.PROXY_NODES.read_bytes(),telegram_file)
        self.assertEqual(self.vpn.status(10,'telegram'),self.telegram)

    def test_admin_edit_of_owned_wireguard_does_not_remove_public_openvpn_nodes(self):
        registry=Registry(self.vpn)
        revision=registry.read('device')[1]
        own={'id':'own-eu','name':'Owned','subnet':'10.200.0.0/24','endpoint':'8.8.8.8:51820',
             'public_key':base64.b64encode(b'x'*32).decode(),'ssh_host':'owned'}
        with patch('backend.registry.detect_location',return_value=None):
            registry.change({'scope':'device','action':'save','expected_revision':revision,'server':own})
        self.assertIn(self.node.id,self.vpn.catalogs['device'])
        self.assertNotIn(self.node.id,self.vpn.nodes)
        self.assertIn('own-eu',self.vpn.nodes)

    def test_public_device_readiness_is_independent_of_ssh_and_telegram(self):
        admin=Admin(self.vpn)
        with patch('backend.admin.wg.load_nodes',return_value={}),patch('backend.admin.proxy.load_nodes',return_value={}),patch('backend.admin.shutil.which',return_value=None),patch('backend.admin.device_vpn.load_nodes',return_value={self.node.id:self.node}),patch.dict('os.environ',{},clear=True):
            result=admin.readiness()
        self.assertTrue(result['device_ready']);self.assertFalse(result['telegram_ready'])

    def test_vpn_country_follows_the_verified_egress_instead_of_source_label(self):
        row=node_row(code='RO')
        with patch('backend.device_vpn.check',return_value={'egress_ip':'1.1.1.1','latency_ms':90}),patch.object(device_refresh,'egress_location',return_value={'country':'BR','country_name':'Brazil'}):
            winners,count=device_refresh.check_candidates([row])
        self.assertEqual(set(winners),{'BR'})
        self.assertTrue(winners['BR']['id'].startswith('ovpn-br-'))

    def test_refresh_conflict_does_not_overwrite_an_administrator_change(self):
        original,revision=device_refresh.read_registry()
        settings.DEVICE_NODES.write_text(json.dumps([node_row('1.1.1.1')]))
        before=settings.DEVICE_NODES.read_bytes()
        with self.assertRaises(ValueError):device_refresh.apply(self.vpn,original,revision,{})
        self.assertEqual(settings.DEVICE_NODES.read_bytes(),before)

    def test_runtime_failure_preserves_registry_instead_of_declaring_all_servers_dead(self):
        before=settings.DEVICE_NODES.read_bytes()
        with patch.object(device_refresh,'require_probe',side_effect=RuntimeError('No Docker')):
            report=device_refresh.refresh(self.vpn)
        self.assertEqual(report['status'],'failed');self.assertEqual(settings.DEVICE_NODES.read_bytes(),before)

    def test_failed_unused_public_server_is_removed_without_touching_owned_nodes(self):
        original,revision=device_refresh.read_registry()
        device_refresh.apply(self.vpn,original,revision,{})
        self.assertNotIn(self.node.id,self.vpn.catalogs['device'])
        self.assertIn('wg-eu',self.vpn.catalogs['device'])

    def test_all_current_device_servers_are_checked_and_healthy_current_wins(self):
        rows=[{**node_row(address),'current':True,'priority':0} for address in ('8.8.8.8','1.1.1.1','9.9.9.9')]
        faster=node_row('8.8.4.4');seen=[]
        def check(node):
            seen.append(node.endpoint)
            return {'egress_ip':node.endpoint.split(':')[0],'latency_ms':10 if node.endpoint.startswith('8.8.4.4:') else 100}
        with patch('backend.device_vpn.check',side_effect=check),patch.object(device_refresh,'egress_location',return_value={'country':'US','country_name':'США'}):
            winners,count=device_refresh.check_candidates([*rows,faster])
        self.assertEqual(count,4)
        self.assertTrue(all(row['endpoint'] in seen for row in rows))
        self.assertTrue(winners['US']['current']);self.assertNotEqual(winners['US']['endpoint'],faster['endpoint'])

    def test_hourly_verification_has_grace_during_the_next_scan(self):
        with patch('backend.device_vpn.time.time',return_value=self.node.checked_at+3601):self.assertTrue(device_vpn.available(self.node))
        with patch('backend.device_vpn.time.time',return_value=self.node.checked_at+7201):self.assertFalse(device_vpn.available(self.node))

    def test_admin_keeps_hourly_vpn_verification_fresh_after_five_minutes(self):
        with patch('time.time',return_value=self.node.checked_at+600):
            server=next(row for row in Admin(self.vpn).servers() if row['id']==self.node.id)
        self.assertEqual(server['metric']['state'],'online')
        self.assertEqual(server['metric']['latency_ms'],self.node.latency_ms)

    def test_required_russia_search_continues_after_the_first_two_failures(self):
        rows=[node_row(address,code='RU') for address in ('8.8.8.8','1.1.1.1','9.9.9.9','8.8.4.4')]
        def check(node):
            if node.endpoint.startswith(('8.8.8.8:','1.1.1.1:')):
                from backend.wireguard import WireGuardError
                raise WireGuardError('offline')
            return {'egress_ip':node.endpoint.split(':')[0],'latency_ms':100}
        with patch('backend.device_vpn.check',side_effect=check),patch.object(device_refresh,'egress_location',return_value={'country':'RU','country_name':'Россия'}):
            verified=[];winners,count=device_refresh.check_candidates(rows,verified)
        self.assertIn('RU',winners)
        self.assertEqual(count,4)
        self.assertEqual(len(verified),2)

    def test_verified_russia_reserves_survive_source_failures(self):
        rows=[node_row('8.8.8.8',code='RU'),node_row('1.1.1.1',code='RU')]
        device_refresh.save_reserves(rows)
        device_refresh.save_reserves([])
        reserves=device_refresh.load_reserves()
        self.assertEqual({row['egress_ip'] for row in reserves},{'8.8.8.8','1.1.1.1'})
        self.assertTrue(all(row['priority']==0 for row in reserves))

    def test_missing_required_russia_cannot_be_reported_as_complete(self):
        with patch('backend.device_vpn.fetch_candidates',return_value=[self.row]),patch('backend.device_vpn.fetch_russian_candidates',return_value=[self.row]),patch.object(device_refresh,'check_candidates',return_value=({'US':self.row},1)):
            report=device_refresh.refresh(self.vpn)
        self.assertEqual(report['status'],'partial')
        self.assertEqual(report['required']['RU'],'missing')
        self.assertNotIn('RU',{row['country'] for row in report['countries']})

    def test_russia_is_first_in_the_separate_device_list(self):
        row=node_row('1.1.1.1',code='RU')
        self.vpn.catalogs['device'].update(device_vpn.parse_nodes([row]))
        self.assertEqual(self.vpn.visible_nodes('device',10)[0]['id'],row['id'])


if __name__=='__main__':unittest.main()
