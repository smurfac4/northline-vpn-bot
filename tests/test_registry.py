from support import install_test_catalogs
import base64
import json
import sqlite3
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import settings
from backend.admin import Admin
from backend.service import VPN, Problem
from backend import wireguard, proxy


class RegistryTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'data').mkdir()
        self.config=patch.multiple(settings,ROOT=self.root,MODE='live',DB=self.root/'data/fixture-vpn.sqlite3',
            NODES=self.root/'nodes.json',PROXY_NODES=self.root/'proxy-nodes.json',DEVICE_NODES=self.root/'device-vpn.json',ADMIN_IDS='10')
        self.config.start();self.addCleanup(self.config.stop)
        lookup=patch('backend.registry.detect_location',return_value=None)
        self.lookup=lookup.start();self.addCleanup(lookup.stop)
        self.vpn=VPN();self.admin=Admin(self.vpn)
        for loader in self.catalog_loaders:loader.stop()
        self.node={'id':'eu-1','name':'Germany','subnet':'10.77.0.0/24','endpoint':'vpn.example.com:51820',
            'public_key':base64.b64encode(b'x'*32).decode(),'ssh_host':'northline-eu-1','enabled':True}

    def version(self,scope='device'):
        return self.admin.real_servers(10)['catalogs'][scope]['revision']

    def save(self,node=None,original=None,version=None,scope='device'):
        return self.admin.edit_real_server(10,{'scope':scope,'action':'save','server':node or self.node,
            'original_id':original,'expected_revision':version or self.version(scope)})


    def test_country_and_flag_are_detected_for_both_server_types(self):
        self.lookup.return_value={'country':'LT','country_name':'Литва'}
        result=self.save({**self.node,'name':''})
        node=wireguard.parse_nodes(json.loads(settings.NODES.read_text()),allow_empty=True)['eu-1']
        self.assertEqual((node.country,node.country_name,node.name),('LT','Литва','🇱🇹 Литва'))
        self.assertEqual(result['location'],'🇱🇹 Литва')
        self.save({'id':'tg-1','name':'My proxy','host':'88.223.117.142','port':8443},scope='telegram')
        node=proxy.parse_nodes(json.loads(settings.PROXY_NODES.read_text()))['tg-1']
        self.assertEqual((node.country,node.country_name,node.name),('LT','Литва','My proxy'))

    def test_name_edits_preserve_country_without_another_network_lookup(self):
        self.lookup.return_value={'country':'LT','country_name':'Литва'};self.save()
        self.lookup.reset_mock()
        self.save({**self.node,'name':'Renamed'},original='eu-1')
        self.lookup.assert_not_called()
        self.assertEqual(wireguard.parse_nodes(json.loads(settings.NODES.read_text()),allow_empty=True)['eu-1'].country,'LT')

    def test_detecting_country_preserves_existing_traffic_measurements(self):
        self.save()
        with self.vpn.db() as db:
            db.execute("INSERT INTO server_metrics(scope,node,sampled_at,state,download_mbps,upload_mbps) VALUES ('device','eu-1',100,'online',12,3)")
        self.lookup.return_value={'country':'LT','country_name':'Литва'}
        self.save(original='eu-1')
        with self.vpn.db() as db:row=db.execute("SELECT * FROM server_metrics WHERE node='eu-1'").fetchone()
        self.assertEqual(row['download_mbps'],12);self.assertEqual(row['upload_mbps'],3)

    def test_new_address_refreshes_country_and_failed_lookup_clears_old_country(self):
        self.lookup.return_value={'country':'LT','country_name':'Литва'};self.save()
        updated={**self.node,'endpoint':'8.8.8.8:51820'}
        self.lookup.return_value={'country':'US','country_name':'США'};self.save(updated,original='eu-1')
        self.assertEqual(wireguard.parse_nodes(json.loads(settings.NODES.read_text()),allow_empty=True)['eu-1'].country,'US')
        self.lookup.return_value=None
        result=self.save({**updated,'endpoint':'1.1.1.1:51820'},original='eu-1')
        node=wireguard.parse_nodes(json.loads(settings.NODES.read_text()),allow_empty=True)['eu-1']
        self.assertEqual(node.country,'');self.assertEqual(node.name,self.node['name'])
        self.assertIn('страну определить не удалось',result['location_warning'])

    def test_geolocation_uses_validated_address_and_ignores_client_country(self):
        self.lookup.return_value={'country':'LT','country_name':'Литва'}
        self.save({**self.node,'country':'US','country_name':'Incorrect'})
        self.assertEqual(wireguard.parse_nodes(json.loads(settings.NODES.read_text()),allow_empty=True)['eu-1'].country,'LT')
        self.lookup.reset_mock()
        with self.assertRaises(Problem):self.save({**self.node,'id':'invalid;','endpoint':'bad..host:1'})
        self.lookup.assert_not_called()

    def test_slow_geolocation_does_not_hold_the_vpn_lock(self):
        done=threading.Event()
        def lookup(host):
            worker=threading.Thread(target=lambda:(self.vpn.status(20),done.set()),daemon=True)
            worker.start();self.assertTrue(done.wait(1));worker.join(1)
            return {'country':'LT','country_name':'Литва'}
        self.lookup.side_effect=lookup
        self.save()

    def test_concurrent_catalog_edit_during_lookup_cannot_be_overwritten(self):
        def lookup(host):
            settings.NODES.write_text(json.dumps([{**self.node,'name':'Other writer'}]))
            return {'country':'LT','country_name':'Литва'}
        self.lookup.side_effect=lookup
        with self.assertRaises(Problem) as error:self.save()
        self.assertEqual(error.exception.status,409)
        self.assertEqual(json.loads(settings.NODES.read_text())[0]['name'],'Other writer')


    def test_edit_creates_private_backup(self):
        self.save();before=settings.NODES.read_bytes()
        self.save({**self.node,'name':'New name'},original='eu-1')
        backups=list((self.root/'registry-backups').glob('*.json'))
        self.assertEqual(len(backups),1);self.assertEqual(backups[0].read_bytes(),before)
        self.assertEqual(backups[0].stat().st_mode&0o777,0o600)

    def test_stale_form_cannot_overwrite_newer_changes(self):
        self.save();old=self.version()
        self.save({**self.node,'name':'Latest'},original='eu-1')
        with self.assertRaises(Problem) as error:self.save({**self.node,'name':'Stale'},'eu-1',old)
        self.assertEqual(error.exception.status,409)
        self.assertEqual(json.loads(settings.NODES.read_text())[0]['name'],'Latest')

    def test_invalid_server_and_unknown_fields_do_not_write_file(self):
        for changes in ({'public_key':'invalid'},{'ssh_host':'host; command'},{'subnet':'8.8.8.0/24'},
                        {'endpoint':'host:70000'},{'endpoint':'bad..host:51820'},{'endpoint':'999.999.999.999:51820'},{'private_key':'must-not-be-stored'},{'enabled':'false'}):
            with self.subTest(changes=changes),self.assertRaises(Problem):self.save({**self.node,**changes})
            self.assertFalse(settings.NODES.exists())

    def test_duplicate_id_and_rename_are_rejected(self):
        self.save()
        with self.assertRaises(Problem):self.save()
        with self.assertRaises(Problem):self.save({**self.node,'id':'different'},original='eu-1')

    def test_overlapping_enabled_subnets_are_rejected(self):
        self.save()
        with self.assertRaises(Problem):self.save({**self.node,'id':'eu-2'})
        self.save({**self.node,'id':'eu-2','enabled':False})
        self.assertEqual(len(wireguard.parse_nodes(json.loads(settings.NODES.read_text()),allow_empty=True)),1)

    def test_proxy_registry_is_independent(self):
        self.save({'id':'tg-eu-1','name':'Germany','host':'proxy.example.com','port':8443,'enabled':True},scope='telegram')
        self.assertFalse(settings.NODES.exists())
        self.assertIn('tg-eu-1',proxy.parse_nodes(json.loads(settings.PROXY_NODES.read_text())))
        self.assertEqual(set(self.vpn.catalogs['telegram']),{'tg-eu-1'})

    def test_missing_or_malformed_file_does_not_crash_admin(self):
        for value in ({},[None],['bad'],[{'id':None}]):
            settings.NODES.write_text(json.dumps(value))
            self.assertIsNotNone(self.admin.real_servers(10)['catalogs']['device']['error'])
            self.assertFalse(self.admin.readiness()['device_ready'])

    def test_inactive_live_profiles_guard_structural_changes(self):
        self.save()
        with self.vpn.db() as db:
            db.execute("INSERT INTO profiles (user_id,scope,node,address,private_key,public_key,state,expires) VALUES (20,'device','eu-1','10.77.0.2','','','active',0)")
        self.save({**self.node,'name':'Cosmetic edit'},original='eu-1')
        for changes in ({'enabled':False},{'endpoint':'other.example.com:51820'}):
            with self.subTest(changes=changes),self.assertRaises(Problem):self.save({**self.node,**changes},original='eu-1')
        with self.assertRaises(Problem):self.admin.edit_real_server(10,{'scope':'device','action':'delete',
            'original_id':'eu-1','expected_revision':self.version(),'confirm':True})

    def test_atomic_write_failure_preserves_old_config(self):
        self.save();before=settings.NODES.read_bytes()
        with patch('backend.registry.os.replace',side_effect=PermissionError('denied')):
            with self.assertRaises(Problem) as error:self.save({**self.node,'name':'not saved'},original='eu-1')
        self.assertEqual(error.exception.status,503);self.assertEqual(settings.NODES.read_bytes(),before)

    def test_non_admin_cannot_modify_registry(self):
        with self.assertRaises(Problem) as error:self.admin.edit_real_server(20,{'scope':'device','action':'save','server':self.node})
        self.assertEqual(error.exception.status,403);self.assertFalse(settings.NODES.exists())

    def test_live_catalog_applies_safe_edits_without_restart(self):
        self.save()
        with patch.object(settings,'MODE','live'),patch.object(settings,'DB',self.root/'data/vpn-live.sqlite3'):
            vpn=VPN();admin=Admin(vpn)
            version=admin.real_servers(10)['catalogs']['device']['revision']
            result=admin.edit_real_server(10,{'scope':'device','action':'save','original_id':'eu-1',
                'expected_revision':version,'server':{**self.node,'name':'Updated'}})
            self.assertTrue(result['applied']);self.assertEqual(vpn.nodes['eu-1'].name,'Updated')
            with self.assertRaises(Problem):admin.edit_real_server(10,{'scope':'device','action':'delete',
                'original_id':'eu-1','expected_revision':admin.real_servers(10)['catalogs']['device']['revision'],'confirm':True})

    def test_confirmed_delete_is_reversible_from_backup(self):
        self.save()
        self.save({**self.node,'id':'eu-2','subnet':'10.78.0.0/24'})
        self.admin.edit_real_server(10,{'scope':'device','action':'delete','original_id':'eu-1',
            'expected_revision':self.version(),'confirm':True})
        self.assertEqual([row['id'] for row in json.loads(settings.NODES.read_text())],['eu-2'])
        self.assertTrue(list((self.root/'registry-backups').glob('*.json')))
