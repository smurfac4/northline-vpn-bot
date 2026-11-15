import unittest
from unittest.mock import patch

from backend import geolocation


class CountryLookupTests(unittest.TestCase):
    def setUp(self):geolocation._cache.clear()

    def test_public_ip_returns_russian_country_and_caches_result(self):
        with patch('backend.geolocation._json',return_value={'success':True,'country_code':'LT','country':'Литва'}) as request:
            first=geolocation.detect_location('88.223.117.142')
            self.assertEqual(first,{'country':'LT','country_name':'Литва'})
            first['country']='XX'
            self.assertEqual(geolocation.detect_location('88.223.117.142')['country'],'LT')
            request.assert_called_once()
            self.assertTrue(request.call_args.args[0].startswith('https://ipwho.is/88.223.117.142?'))

    def test_domain_is_resolved_without_contacting_user_supplied_host(self):
        answers=[{'Status':0,'Answer':[{'type':1,'data':'192.168.1.1'},{'type':1,'data':'8.8.8.8'}]},
                 {'success':True,'country_code':'US','country':'США'}]
        with patch('backend.geolocation._json',side_effect=answers) as request:
            self.assertEqual(geolocation.detect_location('vpn.example.com')['country'],'US')
        self.assertTrue(request.call_args_list[0].args[0].startswith('https://cloudflare-dns.com/dns-query?'))
        self.assertTrue(request.call_args_list[1].args[0].startswith('https://ipwho.is/8.8.8.8?'))

    def test_private_local_and_invalid_hosts_never_reach_provider(self):
        for host in ['127.0.0.1','192.168.0.5','10.0.0.1','169.254.169.254','100.64.0.1','localhost','mac.local','https://example.com','bad..host']:
            with self.subTest(host=host),patch('backend.geolocation._json') as request:
                self.assertIsNone(geolocation.detect_location(host));request.assert_not_called()

    def test_failures_are_not_cached_and_do_not_make_up_a_country(self):
        for value in [{'success':False}, {'success':True,'country_code':'ZZ','country':'Unknown'},
                      {'success':True,'country_code':'LT','country':None},
                      {'success':True,'country_code':'LT','country':'bad\nname'}]:
            with self.subTest(value=value),patch('backend.geolocation._json',return_value=value):
                self.assertIsNone(geolocation.detect_location('8.8.8.8'))
        with patch('backend.geolocation._json',side_effect=TimeoutError):self.assertIsNone(geolocation.detect_location('8.8.8.8'))
        self.assertEqual(geolocation._cache,{})
