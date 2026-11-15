"""Isolated server fixtures; production has no synthetic runtime mode."""
import base64
import hashlib
import ipaddress
from unittest.mock import patch
from backend import proxy, wireguard

LOCATIONS=[('eu','🇩🇪 Германия'),('us','🇺🇸 США'),('gb','🇬🇧 Великобритания'),('ie','🇮🇪 Ирландия'),('nl','🇳🇱 Нидерланды'),('fr','🇫🇷 Франция'),('fi','🇫🇮 Финляндия'),('se','🇸🇪 Швеция'),('pl','🇵🇱 Польша'),('lt','🇱🇹 Литва'),('ch','🇨🇭 Швейцария'),('ca','🇨🇦 Канада'),('jp','🇯🇵 Япония'),('sg','🇸🇬 Сингапур'),('au','🇦🇺 Австралия'),('tr','🇹🇷 Турция')]

def owned_nodes():
    return {'wg-'+code:wireguard.Node('wg-'+code,name,ipaddress.IPv4Network(f'10.{77+i}.0.0/24'),
            endpoint='8.8.8.8:51820',public_key=base64.b64encode(b's'*32).decode(),ssh_host='fixture-node')
            for i,(code,name) in enumerate(LOCATIONS)}

def proxy_nodes():
    return {'tg-'+code:proxy.ProxyNode('tg-'+code,name,'8.8.8.8',443,secret='dd'+'ab'*16) for code,name in LOCATIONS}

def install_test_catalogs(case):
    count=[0]
    def keys():
        count[0]+=1
        return tuple(base64.b64encode(hashlib.sha256((kind+str(count[0])).encode()).digest()).decode() for kind in ('private','public'))
    items=(patch('backend.wireguard.load_nodes',side_effect=owned_nodes),
                 patch('backend.proxy.load_nodes',side_effect=proxy_nodes),
                 patch('backend.device_vpn.load_nodes',return_value={}),
                 patch('backend.wireguard.keys',side_effect=keys),patch('backend.wireguard.control',return_value=''),
                 patch('settings.ALLOW','*'),patch('settings.PERSONAL_TEST',False))
    case.catalog_loaders=items[:2]
    for item in items:
        item.start();case.addCleanup(item.stop)
