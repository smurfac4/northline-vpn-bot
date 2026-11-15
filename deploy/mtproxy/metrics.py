"""Read only aggregate counters from the proxy's container-local metrics port."""
import re
from urllib.request import urlopen


def parse_metrics(text):
    names={'user_octets_from':'rx_bytes','user_octets_to':'tx_bytes','user_connects_curr':'peer_count'}
    totals={key:0 for key in names.values()};found=set()
    for line in text.splitlines():
        match=re.fullmatch(r'mtprotoproxy_(user_octets_from|user_octets_to|user_connects_curr)\{[^}\r\n]*\}\s+([0-9]+)',line)
        if not match and re.match(r'mtprotoproxy_(user_octets_from|user_octets_to|user_connects_curr)\b',line):
            raise ValueError('Invalid proxy counter')
        if match:
            key=names[match[1]];totals[key]+=int(match[2]);found.add(key)
    if found!=set(totals) or any(value>2**63-1 for value in totals.values()):
        raise ValueError('Incomplete proxy counters')
    return totals


def collect():
    with urlopen('http://127.0.0.1:8888/metrics',timeout=.4) as response:
        content=response.read(262145)
    if len(content)>262144:raise ValueError('Proxy metrics response is too large')
    return parse_metrics(content.decode('utf-8'))
