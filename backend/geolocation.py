"""Country lookup for public server addresses, using fixed HTTPS services."""
import ipaddress
import json
import re
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request,urlopen

from backend.catalog import valid_host, country_metadata

_cache={}
_lock=threading.Lock()


def _json(url):
    request=Request(url,headers={'Accept':'application/dns-json' if url.startswith('https://cloudflare-dns.com/') else 'application/json','User-Agent':'Northline/1.0'})
    with urlopen(request,timeout=3) as response:raw=response.read(16385)
    if len(raw)>16384:raise ValueError('Location response is too large')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('Invalid location response')
    return value


def _public_ipv4(host):
    if not valid_host(host):return None
    host=host.rstrip('.').lower()
    try:
        address=ipaddress.IPv4Address(host)
        return str(address) if address.is_global else None
    except ValueError:pass
    if '.' not in host or host.endswith(('.local','.localhost','.internal')):return None
    answer=_json('https://cloudflare-dns.com/dns-query?'+urlencode({'name':host,'type':'A'}))
    if answer.get('Status')!=0:return None
    for row in answer.get('Answer',[]):
        if not isinstance(row,dict) or row.get('type')!=1:continue
        try:address=ipaddress.IPv4Address(row['data'])
        except (KeyError,ValueError,TypeError):continue
        if address.is_global:return str(address)
    return None


def detect_location(host):
    try:
        address=_public_ipv4(host)
        if address is None:return None
        now=time.monotonic()
        with _lock:
            cached=_cache.get(address)
            if cached and cached[0]>now:return dict(cached[1])
        value=_json('https://ipwho.is/'+address+'?'+urlencode({'lang':'ru','fields':'success,country,country_code'}))
        code=value.get('country_code')
        if value.get('success') is not True or not isinstance(code,str) or not re.fullmatch('[A-Z]{2}',code) or code in ('ZZ','XX'):
            return None
        result=country_metadata({'country':code,'country_name':value.get('country')})
        with _lock:
            if len(_cache)>=256:_cache.pop(next(iter(_cache)))
            _cache[address]=(now+3600,dict(result))
        return result
    except (OSError,ValueError,TypeError,KeyError):return None
