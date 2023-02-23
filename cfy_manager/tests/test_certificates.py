import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cfy_manager.utils import certificates


def test_generate_self_signed_cert(tmpdir):
    cert_path, key_path = certificates._generate_ssl_certificate(
        ips=['127.0.0.1', '192.168.2.4'],
        cn='localhost',
        cert_path=tmpdir / 'cert.pem',
        key_path=tmpdir / 'key.pem',
        owner=os.geteuid(),
        group=os.getegid(),
    )

    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    with open(key_path, 'rb') as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(), password=None)
        pubkey = key.public_key()

    # check SANs; both the ips and the CN must be there
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert x509.DNSName('localhost') in sans.value
    assert x509.IPAddress(ipaddress.ip_address('127.0.0.1')) in sans.value
    assert x509.IPAddress(ipaddress.ip_address('192.168.2.4')) in sans.value
    # we also add IPs as DNSname onto the cert, because that's what some
    # browsers want
    assert x509.DNSName('127.0.0.1') in sans.value
    assert x509.DNSName('192.168.2.4') in sans.value

    # check that the cert is actually self-signed - signed by the returned key
    pubkey.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


@dataclass
class _TestCACert:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey
    key_path: str
    cert_path: str
    key_password: str


@pytest.fixture
def ca_cert(tmpdir):
    key_path = tmpdir / 'ca_key.pem'
    cert_path = tmpdir / 'ca_cert.pem'

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,  # no need for a big key in tests
    )
    key_password = 'key_password1'

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(key_password.encode())
        ),
    )
    with open(key_path, 'wb') as key_file:
        key_file.write(key_pem)

    name = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'test'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    return _TestCACert(
        cert=cert,
        key=key,
        key_path=key_path,
        cert_path=cert_path,
        key_password=key_password,
    )


def test_generate_signed_cert(tmpdir, ca_cert):
    cert_path, _ = certificates._generate_ssl_certificate(
        ips=['127.0.0.1'],
        cn='localhost',
        cert_path=tmpdir / 'cert.pem',
        key_path=tmpdir / 'key.pem',
        sign_cert_path=ca_cert.cert_path,
        sign_key_path=ca_cert.key_path,
        sign_key_password=ca_cert.key_password,
        owner=os.geteuid(),
        group=os.getegid(),
    )

    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())

    ca_cert.key.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    # check issuer name - it should be the signing cert's CN, not our own
    issuer_cn_oid = cert.issuer.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME)
    assert len(issuer_cn_oid) == 1
    assert issuer_cn_oid[0].value == 'test'
