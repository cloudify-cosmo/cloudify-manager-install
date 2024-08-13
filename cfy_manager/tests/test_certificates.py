import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from unittest import mock

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cfy_manager.exceptions import ValidationError
from cfy_manager.utils import certificates


@pytest.fixture(autouse=True)
def _mock_small_cert_size():
    """Mock CERT_SIZE to a small value.

    In tests, we don't need to create large certs. Making the size small
    makes these tests faster by an order of magnitude.
    """
    with mock.patch('cfy_manager.utils.certificates.CERT_SIZE', 1024):
        yield


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
        key_size=1024,  # cryptography 42.0.3/changelog/3.3
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
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=False,
        )
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


def test_generate_ca_cert(tmpdir):
    cert_path = tmpdir / 'ca_cert.pem'
    key_path = tmpdir / 'ca_key.pem'

    certificates.generate_ca_cert(cert_path, key_path)

    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    with open(key_path, 'rb') as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(), password=None)

    # check that subject == issuer == hardcoded name
    subject_cn = cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME)[0].value
    issuer_cn = cert.issuer.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME)[0].value
    assert subject_cn.startswith('Cloudify generated certificate')
    assert issuer_cn.startswith('Cloudify generated certificate')

    # check that the cert is marked as a CA
    constraints = cert.extensions.get_extension_for_class(
        x509.BasicConstraints)
    assert constraints.value.ca

    # check that the cert is indeed signed by the key
    key.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def test_check_signed_by_true(tmpdir, ca_cert):
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

    assert certificates.is_signed_by(ca_cert.cert_path, cert_path)


def test_check_signed_by_false(tmpdir, ca_cert):
    # generate a self-signed cert: no sign_key_path supplied
    cert_path, _ = certificates._generate_ssl_certificate(
        ips=['127.0.0.1'],
        cn='localhost',
        cert_path=tmpdir / 'cert.pem',
        key_path=tmpdir / 'key.pem',
        owner=os.geteuid(),
        group=os.getegid(),
    )

    assert not certificates.is_signed_by(ca_cert.cert_path, cert_path)


def test_get_cert_cn(tmpdir, ca_cert):
    cn = certificates.get_cert_cn(ca_cert.cert_path)
    assert cn == 'test'


def test_check_cert_key_match(tmpdir, ca_cert):
    other_cert_path, other_key_path = certificates._generate_ssl_certificate(
        ips=['127.0.0.1'],
        cn='localhost',
        cert_path=tmpdir / 'cert.pem',
        key_path=tmpdir / 'key.pem',
        owner=os.geteuid(),
        group=os.getegid(),
    )

    certificates.check_cert_key_match(
        ca_cert.cert_path,
        ca_cert.key_path,
        password=ca_cert.key_password,
    )
    certificates.check_cert_key_match(
        other_cert_path,
        other_key_path,
    )

    with pytest.raises(ValidationError):
        certificates.check_cert_key_match(
            ca_cert.cert_path,
            other_key_path,
        )

    with pytest.raises(ValidationError):
        certificates.check_cert_key_match(
            other_cert_path,
            ca_cert.key_path,
            password=ca_cert.key_password,
        )


def test_certs_identical(tmpdir, ca_cert):
    other_cert_path, _ = certificates._generate_ssl_certificate(
        ips=['127.0.0.1'],
        cn='localhost',
        cert_path=tmpdir / 'cert.pem',
        key_path=tmpdir / 'key.pem',
        owner=os.geteuid(),
        group=os.getegid(),
    )

    assert certificates.certs_identical(ca_cert.cert_path, ca_cert.cert_path)
    assert not certificates.certs_identical(ca_cert.cert_path, other_cert_path)


def test_check_ssl_file(tmpdir, ca_cert):
    with pytest.raises(ValidationError):
        certificates.check_ssl_file(tmpdir / 'nonexistent')

    with pytest.raises(ValidationError):
        certificates.check_ssl_file(ca_cert.cert_path, kind='Key')

    with pytest.raises(ValidationError):
        certificates.check_ssl_file(ca_cert.key_path, kind='Cert')

    certificates.check_ssl_file(ca_cert.key_path, kind='Key',
                                password=ca_cert.key_password)
    certificates.check_ssl_file(ca_cert.cert_path, kind='Cert')


def test_remove_key_encryption(tmpdir, ca_cert):
    source_key = tmpdir / 'source.pem'
    target_key = tmpdir / 'target.pem'
    password = 'password1'

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    with open(source_key, 'wb') as key_file:
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(password.encode())
            ),
        )
        key_file.write(key_pem)

    certificates.remove_key_encryption(source_key, target_key, password)

    with open(target_key, 'rb') as key_file:
        serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def test_get_cert_sans(tmpdir, ca_cert):
    cert_path, _ = certificates._generate_ssl_certificate(
        ips=['192.168.2.4', 'example.com'],
        cn='localhost',
        cert_path=tmpdir / 'cert.pem',
        key_path=tmpdir / 'key.pem',
        sign_cert_path=ca_cert.cert_path,
        sign_key_path=ca_cert.key_path,
        sign_key_password=ca_cert.key_password,
        owner=os.geteuid(),
        group=os.getegid(),
    )
    sans = certificates.get_cert_sans(cert_path)
    assert set(sans) == {
        x509.DNSName('localhost'),
        x509.DNSName('example.com'),
        x509.DNSName('192.168.2.4'),
        x509.IPAddress(ipaddress.IPv4Address('192.168.2.4')),
    }
