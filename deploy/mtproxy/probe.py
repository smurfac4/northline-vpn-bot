"""Verify a real unauthenticated MTProto resPQ exchange through our proxy."""
import hashlib
import json
import os
import socket
import struct
import sys
import time
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES


def probe(config):
    started=time.monotonic()
    raw_secret=bytes.fromhex(config['secret'])
    tls=config.get('transport')=='tls'
    secret=raw_secret[1:17] if tls else raw_secret
    secure=config.get('transport','secure')!='intermediate'
    header=bytearray(os.urandom(64))
    while header[0] in (0xef,0xee,0xdd) or header[:4] in (b'HEAD',b'POST',b'GET ',b'OPTI') or header[4:8]==b'\0'*4:
        header=bytearray(os.urandom(64))
    reverse=header[8:56][::-1]
    outgoing=AES.new(hashlib.sha256(bytes(header[8:40])+secret).digest(),AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(header[40:56],'big'))
    incoming=AES.new(hashlib.sha256(bytes(reverse[:32])+secret).digest(),AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(reverse[32:48],'big'))
    header[56:60]=(b'\xdd' if secure else b'\xee')*4;header[60:62]=struct.pack('<h',2)
    encrypted=outgoing.encrypt(bytes(header));header[56:64]=encrypted[56:64]
    nonce=os.urandom(16);body=struct.pack('<I',0xbe7e8ef1)+nonce
    envelope=struct.pack('<QQI',0,int(time.time()*2**32)&~3,len(body))+body+(os.urandom(2) if secure else b'')
    with socket.create_connection((config['host'],config['port']),timeout=5) as connection:
        deadline=started+12
        def raw_receive(length):
            data=b''
            while len(data)<length:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('MTProto probe timed out')
                connection.settimeout(min(6,remaining))
                block=connection.recv(length-len(data))
                if not block:raise RuntimeError('MTProto connection closed before a response')
                data+=block
            return data
        payload=bytes(header)+outgoing.encrypt(struct.pack('<I',len(envelope))+envelope)
        if tls:
            # Public checks bundle the reviewed Fake TLS helper ahead of this module.
            hello,digest,session=build_client_hello(secret,raw_secret[17:].decode('ascii'))
            connection.sendall(hello)
            read_and_verify_server_hello(raw_receive,secret,digest,session)
            connection.sendall(b'\x14\x03\x03\x00\x01\x01'+wrap_application_data(payload))
            read=TLSRecordReader(raw_receive).read_exactly
        else:
            connection.sendall(payload)
            read=raw_receive
        def receive(length):
            return incoming.decrypt(read(length))
        length=struct.unpack('<I',receive(4))[0]
        if not 40<=length<=65536:raise RuntimeError('Invalid MTProto response length')
        response=receive(length)
        if struct.unpack_from('<I',response,20)[0]!=0x05162463 or response[24:40]!=nonce:
            raise RuntimeError('Telegram response did not match the requested nonce')
    return {'telegram_response':'resPQ','nonce_verified':True,'bytes_received':length,'roundtrip_ms':round((time.monotonic()-started)*1000,1)}


def main():
    print(json.dumps(probe(json.load(sys.stdin))))


if __name__=='__main__':main()
