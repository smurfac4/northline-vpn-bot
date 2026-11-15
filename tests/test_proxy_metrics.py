import copy
import importlib.util
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from backend import proxy
from backend.wireguard import WireGuardError

spec=importlib.util.spec_from_file_location('proxy_counter_parser',Path(__file__).resolve().parent.parent/'deploy/mtproxy/metrics.py')
parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)


class ProxyCounterTests(unittest.TestCase):
    def test_only_aggregated_counters_leave_the_metrics_parser(self):
        rows=['# TYPE mtprotoproxy_user_octets_from counter','mtprotoproxy_proxy_link_info{secret="PRIVATE"} 1']
        for user,rx,tx,connections in [('profile0',100,200,2),('profile1',300,500,3)]:
            for name,value in [('user_octets_from',rx),('user_octets_to',tx),('user_connects_curr',connections)]:
                rows.append(f'mtprotoproxy_{name}{{user="{user}"}} {value}')
        self.assertEqual(parser.parse_metrics('\n'.join(rows)),{'rx_bytes':400,'tx_bytes':700,'peer_count':5})

    def test_incomplete_invalid_and_overflow_counters_fail_closed(self):
        good='mtprotoproxy_user_octets_from{user="profile0"} 1\nmtprotoproxy_user_octets_to{user="profile0"} 2\nmtprotoproxy_user_connects_curr{user="profile0"} 0'
        self.assertEqual(parser.parse_metrics(good)['peer_count'],0)
        for text in ['',good.replace(' 2',' -1'),good.replace(' 2',' NaN'),good.replace(' 2',' '+str(2**63)),good+'\nmtprotoproxy_user_octets_from{user="extra"} -1']:
            with self.subTest(text=text),self.assertRaises(ValueError):parser.parse_metrics(text)

    def test_backend_accepts_only_fresh_matching_managed_node_counters(self):
        node=proxy.ProxyNode('tg-test','Test','proxy.example.com',8443)
        now=int(time.time())
        good={'host':node.host,'port':node.port,'metrics':{'sampled_at':now,'sample_id':'a'*16,'rx_bytes':123,'tx_bytes':456,'peer_count':2}}
        with patch('settings.MTPROXY_NODE_ID',node.id),patch('backend.proxy.service_status',return_value=good):
            self.assertEqual(proxy.metrics(node),good['metrics'])
        bad=[]
        for key,value in [('host','other.example.com'),('port',443),('metrics',None)]:
            state=copy.deepcopy(good);state[key]=value;bad.append(state)
        for key,value in [('sampled_at',now-30),('sample_id','invalid'),('rx_bytes',True),('tx_bytes',-1),('peer_count',2**64)]:
            state=copy.deepcopy(good);state['metrics'][key]=value;bad.append(state)
        for state in bad:
            with self.subTest(state=state),patch('settings.MTPROXY_NODE_ID',node.id),patch('backend.proxy.service_status',return_value=state),self.assertRaises(WireGuardError):proxy.metrics(node)
