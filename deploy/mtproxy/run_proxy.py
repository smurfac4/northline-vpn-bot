"""Use the already verified public address instead of runtime IP-discovery sites."""
import importlib.util
import ipaddress
import os

spec=importlib.util.spec_from_file_location('northline_transport','/opt/mtprotoproxy/mtprotoproxy.py')
transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)
address=str(ipaddress.IPv4Address(os.environ['NORTHLINE_PROXY_IP']))
transport.init_ip_info=lambda:transport.my_ip_info.update({'ipv4':address,'ipv6':None})
transport.main()
