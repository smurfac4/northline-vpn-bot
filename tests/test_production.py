import importlib.util
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import os
import runpy
from unittest.mock import patch

import settings
from backend.main import API
from backend.service import VPN, Problem
from backend.admin import Admin


class ProductionTests(unittest.TestCase):
    def test_blank_optional_paths_use_defaults_instead_of_the_current_directory(self):
        with patch.dict(os.environ,{key:'' for key in ('DB_PATH','NODES_PATH','PROXY_NODES_PATH','DEVICE_NODES_PATH','MTPROXY_STATE_DIR','SSH_CONFIG','PORT','WG_BIN')}):
            config=runpy.run_path(str(settings.ROOT/'settings.py'))
        self.assertEqual(config['DB'],settings.ROOT/'data/vpn-live.sqlite3')
        self.assertEqual(config['NODES'],settings.ROOT/'nodes.json')
        self.assertEqual(config['PROXY_NODES'],settings.ROOT/'proxy-nodes.json')
        self.assertEqual(config['PORT'],8000);self.assertEqual(config['WG_BIN'],'wg')

    def test_relative_paths_are_anchored_to_the_application_directory(self):
        with patch.dict(os.environ,{'DB_PATH':'data/custom.sqlite3','NODES_PATH':'data/owned.json',
                                   'PROXY_NODES_PATH':'data/proxies.json','DEVICE_NODES_PATH':'data/device.json',
                                   'MTPROXY_STATE_DIR':'data/mtproto','SSH_CONFIG':'data/ssh.config'}):
            config=runpy.run_path(str(settings.ROOT/'settings.py'))
        for key,path in {'DB':'data/custom.sqlite3','NODES':'data/owned.json','PROXY_NODES':'data/proxies.json',
                         'DEVICE_NODES':'data/device.json','MTPROXY_STATE_DIR':'data/mtproto','SSH_CONFIG':'data/ssh.config'}.items():
            self.assertEqual(Path(config[key]),settings.ROOT/path)

    def test_invalid_listening_port_is_rejected_early(self):
        for value in ('0','65536','-1'):
            with self.subTest(value=value),patch.dict(os.environ,{'PORT':value}):
                with self.assertRaisesRegex(ValueError,'PORT'):
                    runpy.run_path(str(settings.ROOT/'settings.py'))

    def test_missing_credentials_never_enable_anonymous_access(self):
        handler=object.__new__(API);handler.headers={}
        with patch.multiple(settings,TOKEN='',BOT_KEY=''):
            with self.assertRaises(Problem) as error:handler.actor()
        self.assertEqual(error.exception.status,401)

    def test_empty_installation_has_no_invented_countries_or_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.multiple(settings,DB=root/'vpn.sqlite3',NODES=root/'owned.json',PROXY_NODES=root/'telegram.json',DEVICE_NODES=root/'device.json',MTPROXY_NODE_ID=''):
                vpn=VPN()
                self.assertEqual(vpn.visible_nodes('device'),[]);self.assertEqual(vpn.visible_nodes('telegram'),[])
                self.assertFalse(vpn.available('device'));self.assertFalse(vpn.available('telegram'))
                self.assertEqual(vpn.status(10)['status'],'none')
        self.assertFalse(hasattr(Admin,'environment'))

    def test_hosting_bundle_excludes_private_and_local_runtime_files(self):
        spec=importlib.util.spec_from_file_location('packager',Path(__file__).resolve().parent.parent/'deploy/package.py')
        package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory() as directory:
            target=package.build(Path(directory)/'hosting.tar.gz')
            with tarfile.open(target) as archive:
                names=set(archive.getnames())
                for name in names:
                    self.assertNotIn('/data/',name);self.assertNotIn('registry-backups',name)
                    self.assertNotIn('__pycache__',name);self.assertFalse(name.endswith('/.env'))
                    self.assertNotIn('start-local.py',name);self.assertNotIn('pc-test.py',name)
                for required in ('run.py','settings.py','.env.example','backend/main.py','backend/web/app.js','deploy/device-probe/probe.py','deploy/mtproxy/probe.py'):
                    self.assertIn('northline/'+required,names)
