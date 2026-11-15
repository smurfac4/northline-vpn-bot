import hashlib
import hmac
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('faketls_probe', Path(__file__).resolve().parents[1]/'deploy/mtproxy/faketls.py')
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


class FakeTLSProbeTests(unittest.TestCase):
    secret = b'a' * 16

    def reply(self, digest, session):
        body = b'\x03\x03' + b'\0' * 32 + b'\x20' + session + b'\x13\x01\x00\x00\x00'
        handshake = b'\x02' + len(body).to_bytes(3, 'big') + body
        wire = bytearray(b'\x16\x03\x03' + struct.pack('>H', len(handshake)) + handshake
                         + b'\x14\x03\x03\x00\x01\x01' + tls.wrap_application_data(b'certificate'))
        wire[11:43] = hmac.digest(self.secret, digest + bytes(wire), 'sha256')
        return bytes(wire)

    def test_client_hello_authenticates_the_domain_and_timestamp(self):
        with patch('time.time', return_value=1794262000):
            hello, digest, session = tls.build_client_hello(self.secret, 'example.com')
        self.assertEqual(len(hello), 517)
        self.assertIn(b'example.com', hello)
        self.assertEqual(hello[44:76], session)
        zeroed = bytearray(hello); zeroed[11:43] = b'\0' * 32
        expected = bytearray(hmac.digest(self.secret, zeroed, 'sha256'))
        for index, byte in enumerate(struct.pack('<I', 1794262000)):
            expected[28+index] ^= byte
        self.assertEqual(digest, expected)

    def test_signed_server_response_is_accepted(self):
        _, digest, session = tls.build_client_hello(self.secret, 'example.com')
        tls.read_and_verify_server_hello(io.BytesIO(self.reply(digest, session)).read, self.secret, digest, session)

    def test_corrupt_server_response_and_wrong_session_are_rejected(self):
        _, digest, session = tls.build_client_hello(self.secret, 'example.com')
        corrupt = bytearray(self.reply(digest, session)); corrupt[-1] ^= 1
        for wire in (bytes(corrupt), self.reply(digest, b'b' * 32)):
            with self.subTest(wire=wire[:10]), self.assertRaises(tls.FakeTLSError):
                tls.read_and_verify_server_hello(io.BytesIO(wire).read, self.secret, digest, session)

    def test_record_reader_preserves_data_across_record_boundaries(self):
        data = b'mtproto' * 6000
        reader = tls.TLSRecordReader(io.BytesIO(tls.wrap_application_data(data)).read)
        self.assertEqual(reader.read_exactly(19), data[:19])
        self.assertEqual(reader.read_exactly(len(data)-19), data[19:])

    def test_record_reader_rejects_alerts_and_oversized_records(self):
        for header in (b'\x15\x03\x03\x00\x01', b'\x17\x03\x03\xff\xff'):
            with self.subTest(header=header), self.assertRaises(tls.FakeTLSError):
                tls.TLSRecordReader(io.BytesIO(header).read).read_exactly(1)


if __name__ == '__main__':
    unittest.main()
