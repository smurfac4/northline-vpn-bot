import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call,patch

import settings
from backend import wireguard as wg
from backend.admin import Admin


class PersonalNodeTests(unittest.TestCase):
    def test_personal_mode_requires_one_allowed_administrator(self):
        with patch.multiple(settings,PERSONAL_TEST=True,ADMIN_IDS='10,11'):
            for allowed,expected in [('10',10),('11',11),('*',None),('10,11',None),('20',None),('',None),('0',None)]:
                with patch.object(settings,'ALLOW',allowed):self.assertEqual(settings.personal_test_owner(),expected)
        with patch.multiple(settings,PERSONAL_TEST=False,ADMIN_IDS='10',ALLOW='10'):
            self.assertIsNone(settings.personal_test_owner())

    def test_temporary_https_is_only_ready_for_restricted_personal_test(self):
        admin=object.__new__(Admin)
        with patch.multiple(settings,PERSONAL_TEST=True,ADMIN_IDS='10',ALLOW='10',TOKEN='token',BOT_KEY='internal',PUBLIC_URL='https://test.trycloudflare.com'),patch.dict(os.environ,{},clear=True),patch('backend.admin.shutil.which',return_value='/tool'),patch('backend.admin.wg.load_nodes',return_value={'pc':object()}):
            self.assertTrue(admin.readiness()['device_ready'])
            with patch.object(settings,'ALLOW','*'):self.assertFalse(admin.readiness()['device_ready'])
            with patch.object(settings,'PERSONAL_TEST',False):self.assertFalse(admin.readiness()['device_ready'])

    def test_keys_use_configured_binary_without_private_key_in_arguments(self):
        with patch.object(settings,'WG_BIN','/private/tools/wg'),patch('backend.wireguard.run',side_effect=['PRIVATE','PUBLIC']) as run:
            self.assertEqual(wg.keys(),('PRIVATE','PUBLIC'))
        self.assertEqual(run.call_args_list,[call('/private/tools/wg','genkey'),call('/private/tools/wg','pubkey',data='PRIVATE\n')])

    def test_dedicated_ssh_config_keeps_strict_host_verification(self):
        node=type('Node',(),{'ssh_host':'pc-test'})()
        with patch.object(settings,'SSH_CONFIG','/private/node/ssh.config'),patch('backend.wireguard.run') as run:
            wg.control(node,'metrics')
        command=run.call_args.args
        self.assertEqual(command[:3],('ssh','-F','/private/node/ssh.config'))
        self.assertIn('StrictHostKeyChecking=yes',command)
        self.assertEqual(command[-2:],('pc-test','metrics'))

    def test_personal_client_config_uses_tested_mtu(self):
        node=type('Node',(),{'public_key':'PUBLIC','endpoint':'test.example:51820'})()
        with patch.object(settings,'PERSONAL_TEST',True):self.assertIn('MTU = 1380',wg.client_config(node,'PRIVATE','10.253.77.2'))
        with patch.object(settings,'PERSONAL_TEST',False):self.assertNotIn('MTU =',wg.client_config(node,'PRIVATE','10.253.77.2'))


class RouterTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('pc_test',Path(__file__).resolve().parents[1]/'deploy/pc-test.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.router=object.__new__(self.module.Router);self.router.address='192.168.0.5'

    def test_foreign_mapping_is_never_overwritten_or_deleted(self):
        foreign={'NewInternalClient':'192.168.0.9','NewInternalPort':'51820','NewPortMappingDescription':'Other project'}
        with patch.object(self.router,'mapping',return_value=foreign),patch.object(self.router,'call') as call:
            with self.assertRaises(RuntimeError):self.router.add()
            with self.assertRaises(RuntimeError):self.router.remove()
        call.assert_not_called()

    def test_mapping_has_one_hour_lease_and_is_verified(self):
        ours={'NewInternalClient':'192.168.0.5','NewInternalPort':'51820','NewPortMappingDescription':'Northline PC test'}
        with tempfile.TemporaryDirectory() as folder,patch.object(self.module,'STATE',Path(folder)),patch.object(self.module,'urlopen',return_value=io.BytesIO(b'88.223.117.142')),patch.object(self.router,'mapping',side_effect=[None,ours]),patch.object(self.router,'call',side_effect=[{'NewExternalIPAddress':'88.223.117.142'},{}]) as call,patch('builtins.print'):
            self.router.gateway='192.168.0.1';self.router.add()
            self.assertEqual(call.call_args_list[1].args[1]['NewLeaseDuration'],3600)
            self.assertEqual(call.call_args_list[1].args[1]['NewInternalClient'],'192.168.0.5')
            self.assertEqual(json.loads((Path(folder)/'network.json').read_text())['lease_seconds'],3600)

    def test_probe_still_revokes_its_peer_when_container_cleanup_fails(self):
        module=self.module
        responses=['PRIVATE','PUBLIC','SERVER','', 'container-id','bridge',json.dumps({'egress_ip':'88.223.117.142','handshake':1,'rx_bytes':100,'tx_bytes':100}),RuntimeError('docker cleanup failed'),'']
        with tempfile.TemporaryDirectory() as folder,patch.object(module,'STATE',Path(folder)),patch.object(module,'owned_container',return_value={'State':{'Running':True}}),patch.object(module,'run',side_effect=responses) as run,patch('builtins.print'):
            (Path(folder)/'network.json').write_text(json.dumps({'public_ip':'88.223.117.142'}))
            with self.assertRaisesRegex(RuntimeError,'docker cleanup failed'):module.probe()
        self.assertEqual(run.call_args.args[-2:],('remove','PUBLIC'))

    def test_probe_refuses_host_network_before_starting_client(self):
        module=self.module
        with tempfile.TemporaryDirectory() as folder,patch.object(module,'STATE',Path(folder)),patch.object(module,'owned_container',return_value={'State':{'Running':True}}),patch.object(module,'run',side_effect=['PRIVATE','PUBLIC','SERVER','','container-id','host','','']) as run:
            (Path(folder)/'network.json').write_text(json.dumps({'public_ip':'88.223.117.142'}))
            with self.assertRaisesRegex(RuntimeError,'own bridge-network'):module.probe()
        self.assertFalse(any(call.args[:2]==('docker','start') for call in run.call_args_list))
