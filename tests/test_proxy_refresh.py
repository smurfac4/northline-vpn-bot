from support import install_test_catalogs
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import settings
from backend import proxy, proxy_refresh as refresh
from backend.registry import Registry
from backend.service import VPN, Problem
from backend.wireguard import WireGuardError


SECRET = 'ab' * 16


def server(node_id='public-de', host='8.8.8.8', code='DE'):
    return {'id': node_id, 'name': 'Germany', 'host': host, 'port': 443,
            'country': code, 'country_name': 'Германия' if code == 'DE' else 'Франция',
            'secret': SECRET, 'enabled': True}


class RefreshParsingTests(unittest.TestCase):
    def test_html_parser_extracts_country_latency_and_normalized_credentials(self):
        page = refresh.ProxyPage()
        page.feed('<a href="/proxy/fi">Finland</a><article data-server="8.8.8.8" data-port="443" data-secret="' + SECRET + '">'
                  '<a href="/proxy/de">Germany</a><div>latency</div><div>12 <small>ms</small></div></article>')
        self.assertEqual(page.countries, {'fi', 'de'})
        self.assertEqual(len(page.rows), 1)
        self.assertEqual(page.rows[0]['hint'], 'DE')
        self.assertEqual(page.rows[0]['rank'], 12)

    def test_candidate_rejects_private_addresses_bad_ports_and_unprobeable_secrets(self):
        for host, port, secret in [('127.0.0.1', 443, SECRET), ('10.0.0.2', 443, SECRET),
                                   ('8.8.8.8', 70000, SECRET), ('8.8.8.8', 443, 'invalid'),
                                   ('8.8.8.8', 443, 'ee12')]:
            with self.subTest(host=host, port=port, secret=secret):
                self.assertIsNone(refresh.candidate(host, port, secret))

    def test_one_source_failure_does_not_discard_the_other_source(self):
        def source(url):
            if url == refresh.LIST_URL:
                raise OSError('offline')
            return '<article data-server="8.8.8.8" data-port="443" data-secret="' + SECRET + '"></article>'
        with patch.object(refresh, 'fetch', side_effect=source):
            rows, errors = refresh.discover()
        self.assertEqual(len(rows), 1)
        self.assertEqual(errors, ['MTProxy_list: unavailable'])

    def test_supplemental_links_accept_faketls_and_html_escaping(self):
        secret = 'ee' + SECRET + b'example.com'.hex()
        rows = refresh.parse_links('https://t.me/proxy?server=8.8.8.8&amp;port=443&amp;secret=' + secret, 'HK')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['hint'], 'HK')
        self.assertEqual(rows[0]['secret'], secret)

    def test_vanced_loader_limits_discovery_to_required_countries(self):
        html = ''.join('<div class="proxy-card other"><img src="/flags/4x3/'+cc+'.svg">'
                       '<a href="tg://proxy?server='+host+'&port=443&secret='+SECRET+'">Connect</a></div>'
                       for cc, host in [('ru','8.8.8.8'), ('ie','1.1.1.1'), ('hk','9.9.9.9')])
        with patch.object(refresh, 'fetch', return_value=html):
            rows = refresh.load_extra('vanced', 'https://example.com')
        self.assertEqual([row['hint'] for row in rows], ['RU'])

    def test_required_country_uses_two_geolocation_backups_when_primary_fails(self):
        row = refresh.candidate('8.8.8.8', 443, SECRET, 'RU')
        with patch.object(refresh, 'detect_location', return_value=None), patch.object(refresh, '_public_ipv4', return_value='8.8.8.8'), patch.object(refresh, '_json', side_effect=[{'country_code':'RU'}, {'country':'RU'}]):
            self.assertEqual(refresh.locate_candidate(row)['country'], 'RU')

    def test_conflicting_backup_geolocation_does_not_invent_the_required_country(self):
        row = refresh.candidate('8.8.8.8', 443, SECRET, 'RU')
        with patch.object(refresh, 'detect_location', return_value=None), patch.object(refresh, '_public_ipv4', return_value='8.8.8.8'), patch.object(refresh, '_json', side_effect=[{'country_code':'GB'}, {'country':'RU'}]):
            self.assertIsNone(refresh.locate_candidate(row))

    def test_rate_limited_geolocation_does_not_block_the_independent_backup(self):
        row = refresh.candidate('8.8.8.8', 443, SECRET, 'RU')
        with patch.object(refresh, 'detect_location', return_value=None), patch.object(refresh, '_public_ipv4', return_value='8.8.8.8'), patch.object(refresh, '_json', side_effect=[OSError('rate limited'), {'country':'RU'}]):
            self.assertEqual(refresh.locate_candidate(row)['country'], 'RU')

    def test_selects_fastest_successful_mtproto_response_per_actual_country(self):
        rows = [refresh.candidate(host, 443, SECRET, hint='US', rank=rank)
                for host, rank in [('8.8.8.8', 10), ('1.1.1.1', 20), ('9.9.9.9', 30), ('8.8.4.4', 40)]]
        def locate(host):
            return {'country': 'FR' if host == '9.9.9.9' else 'DE', 'country_name': 'France' if host == '9.9.9.9' else 'Germany'}
        def measure(node):
            if node.host == '8.8.4.4':
                raise WireGuardError('unavailable')
            return {'8.8.8.8': 100, '1.1.1.1': 20, '9.9.9.9': 50}[node.host]
        with patch.object(refresh, 'detect_location', side_effect=locate), patch.object(refresh.public_proxy, 'check', side_effect=measure):
            winners = refresh.choose_fastest(rows)
        self.assertEqual(set(winners), {'DE', 'FR'})
        self.assertEqual(winners['DE']['host'], '1.1.1.1')

    def test_checks_current_proxy_outside_shortlist_and_does_not_rotate_a_healthy_endpoint(self):
        rows=[refresh.candidate('8.8.8.8',443,SECRET,rank=1) for _ in range(8)]
        current={**refresh.candidate('1.1.1.1',443,SECRET,rank=60000),'current':True,'known_name':'Германия'}
        seen=[]
        def check(node):seen.append(node.host);return 100 if node.host=='1.1.1.1' else 10
        with patch.object(refresh,'detect_location',return_value={'country':'DE','country_name':'Германия'}),patch.object(refresh.public_proxy,'check',side_effect=check):
            winners=refresh.choose_fastest([*rows,current])
        self.assertIn('1.1.1.1',seen);self.assertEqual(winners['DE']['host'],'1.1.1.1')

    def test_search_expands_when_current_and_first_candidate_batch_are_dead(self):
        rows=[refresh.candidate('8.8.8.'+str(index),443,SECRET,rank=index) for index in range(1,10)]
        current={**refresh.candidate('8.8.4.4',443,SECRET,rank=1),'current':True}
        def check(node):
            if node.host!='8.8.8.9':raise WireGuardError('offline')
            return 20
        with patch.object(refresh,'detect_location',return_value={'country':'DE','country_name':'Германия'}),patch.object(refresh.public_proxy,'check',side_effect=check):
            winners=refresh.choose_fastest([current,*rows])
        self.assertEqual(winners['DE']['host'],'8.8.8.9')


class RefreshCatalogTests(unittest.TestCase):
    def setUp(self):
        install_test_catalogs(self)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = patch.multiple(settings, MODE='live', ROOT=self.root, DB=self.root/'profiles.db',
                                PROXY_NODES=self.root/'proxy.json', MTPROXY_NODE_ID='managed', ALLOW='*', PERSONAL_TEST=False)
        config.start(); self.addCleanup(config.stop)
        runtime=patch.object(refresh,'require_probe'); runtime.start(); self.addCleanup(runtime.stop)
        self.vpn = VPN()
        live = patch.object(settings, 'MODE', 'live'); live.start(); self.addCleanup(live.stop)
        self.rows = [server()]
        settings.PROXY_NODES.write_text(json.dumps(self.rows))
        self.vpn.catalogs['telegram'] = proxy.parse_nodes(self.rows)
        self.revision = Registry(self.vpn).read('telegram')[1]
        self.winner = {**refresh.candidate('1.1.1.1', 443, SECRET), 'country': 'DE',
                       'country_name': 'Германия', 'latency_ms': 20}

    def apply(self, winners=None, managed=None):
        return refresh.apply(self.vpn, self.rows, self.revision,
                             {'DE': self.winner} if winners is None else winners, managed)

    def test_replacement_keeps_active_old_profile_but_shows_one_current_country(self):
        original = self.vpn.issue(1, 'public-de', scope='telegram')
        self.apply()
        self.assertEqual(self.vpn.status(1, 'telegram')['id'], original['id'])
        self.assertTrue(self.vpn.status(1,'telegram')['node_retired'])
        with self.assertRaises(Problem) as error:self.vpn.connection(1,'telegram')
        self.assertEqual(error.exception.status,409)
        self.assertIsNotNone(self.vpn.status(1,'telegram')['replacement'])
        visible = self.vpn.visible_nodes('telegram', 1)
        self.assertEqual(len(visible), 1)
        self.assertNotEqual(visible[0]['id'], 'public-de')
        self.assertTrue(self.vpn.catalogs['telegram']['public-de'].retired)
        with self.assertRaises(Problem):
            self.vpn.issue(2, 'public-de', scope='telegram')
        self.assertTrue(list((self.root/'registry-backups').glob('*.json')))

    def test_unused_previous_proxy_is_removed(self):
        self.apply()
        self.assertNotIn('public-de', self.vpn.catalogs['telegram'])
        self.assertEqual(len(self.vpn.visible_nodes('telegram', 1)), 1)

    def test_failed_runtime_does_not_delete_servers_or_profiles(self):
        profile=self.vpn.issue(1,'public-de',scope='telegram');before=settings.PROXY_NODES.read_bytes()
        with patch.object(refresh,'require_probe',side_effect=RuntimeError('No Docker')):
            report=refresh.refresh(self.vpn)
        self.assertEqual(report['status'],'failed');self.assertEqual(settings.PROXY_NODES.read_bytes(),before)
        self.assertEqual(self.vpn.status(1,'telegram'),profile)

    def test_dead_active_node_is_hidden_then_removed_after_profile_release(self):
        profile=self.vpn.issue(1,'public-de',scope='telegram');self.apply({})
        self.assertEqual(self.vpn.visible_nodes('telegram',1),[])
        self.assertTrue(self.vpn.status(1,'telegram')['node_retired'])
        self.assertIsNone(self.vpn.status(1,'telegram')['replacement'])
        self.vpn.revoke(1,profile['id'],'active','telegram')
        original,revision,_=Registry(self.vpn).read('telegram')
        refresh.apply(self.vpn,original,revision,{},None)
        self.assertEqual(self.vpn.catalogs['telegram'],{})

    def test_source_outage_rechecks_saved_proxy_and_keeps_it_when_it_works(self):
        seen=[]
        def choose(rows,verified):
            seen.extend(rows)
            return {'DE':{**rows[0],'country':'DE','country_name':'Германия','latency_ms':20}}
        with patch.object(refresh,'refresh_managed',return_value=None),patch.object(refresh,'discover',return_value=([],['source unavailable'])),patch.object(refresh,'choose_fastest',side_effect=choose):
            report=refresh.refresh(self.vpn)
        self.assertTrue(seen[0]['current'])
        self.assertEqual(self.vpn.visible_nodes('telegram',1)[0]['id'],'public-de')
        self.assertEqual(report['interval_seconds'],3600);self.assertEqual(report['next_check_at'],report['started_at']+3600)

    def test_same_winner_keeps_existing_profile_id_and_node_id(self):
        old = self.vpn.issue(1, 'public-de', scope='telegram')
        self.winner['host'] = '8.8.8.8'
        self.apply()
        self.assertEqual(self.vpn.status(1, 'telegram')['id'], old['id'])
        self.assertEqual(self.vpn.visible_nodes('telegram', 1)[0]['id'], 'public-de')

    def test_no_verified_winners_removes_unavailable_unused_nodes(self):
        self.apply({})
        self.assertEqual(json.loads(settings.PROXY_NODES.read_text()), [])
        self.assertEqual(self.vpn.visible_nodes('telegram',1),[])

    def test_concurrent_administrator_edit_is_not_overwritten(self):
        settings.PROXY_NODES.write_text(json.dumps([server(host='9.9.9.9')]))
        before = settings.PROXY_NODES.read_bytes()
        with self.assertRaises(Problem) as error:
            self.apply()
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(settings.PROXY_NODES.read_bytes(), before)

    def test_managed_ip_updates_without_revoking_its_profile(self):
        managed = {key: value for key, value in server('managed', code='LT').items() if key != 'secret'}
        managed['country_name'] = 'Литва'
        self.rows = [managed]
        settings.PROXY_NODES.write_text(json.dumps(self.rows))
        self.revision = Registry(self.vpn).read('telegram')[1]
        self.vpn.catalogs['telegram'] = proxy.parse_nodes(self.rows)
        with patch('backend.proxy.available', return_value=True), patch('backend.proxy.sync'):
            old = self.vpn.issue(1, 'managed', scope='telegram')
        self.apply({}, {**managed, 'host': '1.1.1.1'})
        self.assertEqual(self.vpn.status(1, 'telegram')['id'], old['id'])
        self.assertEqual(self.vpn.catalogs['telegram']['managed'].host, '1.1.1.1')

    def test_local_refresh_failure_does_not_prevent_public_refresh(self):
        with patch.object(refresh, 'refresh_managed', side_effect=subprocess.TimeoutExpired('local', 40)), patch.object(refresh, 'discover', return_value=([], [])), patch.object(refresh, 'choose_fastest', return_value={'DE': self.winner}):
            refresh.refresh(self.vpn)
        report = json.loads((self.root/'data/proxy-refresh.json').read_text())
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['lithuania'], 'previous endpoint retained')
        self.assertEqual(report['countries'][0]['country'], 'DE')
        self.assertNotIn(SECRET, json.dumps(report))

    def test_required_country_reserves_survive_a_failed_scan(self):
        verified = [{**self.winner, 'country': 'RU'}, {**self.winner, 'host': '9.9.9.9', 'country': 'US'}]
        refresh.save_reserves(verified)
        refresh.save_reserves([])
        reserves = refresh.load_reserves()
        self.assertEqual({row['hint'] for row in reserves}, {'RU', 'US'})
        self.assertTrue(all(row['rank'] == 1 for row in reserves))

    def test_required_countries_are_sorted_first_and_ireland_is_optional(self):
        rows = [server('de', code='DE'), server('hk', code='HK'), server('us', code='US'),
                server('ru', code='RU')]
        self.vpn.catalogs['telegram'] = proxy.parse_nodes(rows)
        visible = self.vpn.visible_nodes('telegram', 1)
        self.assertEqual([row['id'] for row in visible], ['ru','us','de','hk'])
        self.assertNotIn('IE', refresh.REQUIRED_PUBLIC)
        self.assertNotIn('HK', refresh.REQUIRED_PUBLIC)

    def test_missing_required_country_is_reported_without_inventing_a_server(self):
        with patch.object(refresh, 'refresh_managed', return_value=None), patch.object(refresh, 'discover', return_value=([], [])), patch.object(refresh, 'choose_fastest', return_value={}):
            refresh.refresh(self.vpn)
        report = json.loads((self.root/'data/proxy-refresh.json').read_text())
        self.assertEqual(report['required']['RU'], 'missing')
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(self.vpn.visible_nodes('telegram', 1)), 0)


if __name__ == '__main__':
    unittest.main()
