import argh
import grp
import itertools
import json
import os
import pwd
import string
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import network
from .common import chown, chmod, copy, move, run
from ..components_constants import SSL_INPUTS
from ..config import config
from ..constants import (
    BROKER_CERT_LOCATION,
    BROKER_KEY_LOCATION,
    CLOUDIFY_GROUP,
    CLOUDIFY_USER,
    SSL_CERTS_TARGET_DIR,
)
from ..exceptions import ProcessExecutionError
from .files import write

from ..logger import get_logger, setup_console_logger
from .. import constants as const
from cfy_manager.exceptions import ValidationError

logger = get_logger('Certificates')


CERT_SIZE = 4096


def get_cert_cn(cert_path):
    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())

    try:
        return cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)[0].value
    except IndexError:
        return None


def handle_ca_cert(logger, generate_if_missing=True):
    """
    The user might provide both the CA key and the CA cert, or just the
    CA cert, or nothing. It is an error to only provide the CA key.
    If the user provided nothing, we must generate a CA cert+key.
    :return: True if there's a CA key available (either passed or
    generated)
    """
    if _ca_cert_deployed():
        # CA certificate already deployed, no action required
        return os.path.exists(const.CA_KEY_PATH)
    logger.info('Handling CA certificate...')

    ca_cert_source = config[SSL_INPUTS]['ca_cert_path']
    ca_key_source = config[SSL_INPUTS]['ca_key_path']
    ca_deploy_kwargs = {'prefix': 'ca_'}

    has_ca_key = False

    if ca_key_source:
        ca_deploy_kwargs['key_destination'] = const.CA_KEY_PATH

    if ca_cert_source:
        if ca_key_source:
            kwarg = 'cert_destination'
        else:
            kwarg = 'ca_destination'
            ca_deploy_kwargs['just_ca_cert'] = True
        ca_deploy_kwargs[kwarg] = const.CA_CERT_PATH

        # We only try to install these if the cert was supplied
        use_supplied_certificates(
            SSL_INPUTS,
            logger,
            **ca_deploy_kwargs
        )

        logger.info('Deployed user provided CA cert')
        if ca_key_source:
            # If a ca key source was provided and we deployed the cert, we
            # must also have deployed the key or use_supplied_certs would've
            # failed
            has_ca_key = True
            logger.info('Deployed user provided CA key')
    elif generate_if_missing:
        logger.info('Generating CA certificate...')
        if not os.path.exists(SSL_CERTS_TARGET_DIR):
            run(['mkdir', '-p', SSL_CERTS_TARGET_DIR])
        generate_ca_cert()
        has_ca_key = True

    return has_ca_key


def _ca_cert_deployed():
    if config[SSL_INPUTS]['ca_cert_path']:  # Certificate provided
        if os.path.exists(const.CA_CERT_PATH):
            return certs_identical(config[SSL_INPUTS]['ca_cert_path'],
                                   const.CA_CERT_PATH)
        else:
            return False
    else:
        return os.path.exists(const.CA_CERT_PATH)


def store_cert_metadata(hostname=None,
                        new_brokers=None,
                        new_managers=None,
                        new_networks=None,
                        filename=const.CERT_METADATA_FILE_PATH,
                        owner=const.CLOUDIFY_USER,
                        group=const.CLOUDIFY_GROUP):
    metadata = load_cert_metadata(filename=filename)
    if hostname:
        metadata['hostname'] = hostname
    if new_brokers:
        brokers = metadata.get('broker_addresses', [])
        brokers.extend(new_brokers)
        # Add, deduplicated
        metadata['broker_addresses'] = list(set(brokers))
    if new_managers:
        managers = metadata.get('manager_addresses', [])
        managers.extend(new_managers)
        # Add, deduplicated
        metadata['manager_addresses'] = list(set(managers))
    if new_networks:
        networks = metadata.get('network_names', [])
        networks.extend(new_networks)
        # Add, deduplicated
        metadata['network_names'] = list(set(networks))
    write(metadata, filename, json_dump=True,
          owner=owner, group=group, mode=0o640)


def load_cert_metadata(filename=const.CERT_METADATA_FILE_PATH):
    try:
        # Don't use open because file permissions may cause us to load
        # nothing then stomp the contents if we do
        return json.loads(run(['cat', filename]).aggr_stdout)
    except ProcessExecutionError:
        return {}


def _generate_ssl_certificate(
    ips: list[str],
    cn: str,
    cert_path: str | Path,
    key_path: str | Path,
    sign_cert_path: str | Path = None,
    sign_key_path: str | Path = None,
    sign_key_password: str = None,
    key_perms: int = 0o440,
    cert_perms: int = 0o444,
    owner: str | int = 'cfyuser',
    group: str | int = 'cfyuser',
):
    """Generate a public SSL certificate and a private SSL key

    :param ips: the ips (or names) to be used for subjectAltNames
    :param cn: the subject commonName for the new certificate
    :param cert_path: path to save the new certificate to
    :param key_path: path to save the key for the new certificate to
    :param sign_cert: path to the signing cert (self-signed by default)
    :param sign_key: path to the signing cert's key (self-signed by default)
    :param key_perms: permissions to apply to created key file
    :param cert_perms: permissions to apply to created cert file
    :param owner: owner of key and certificate
    :param group: group of key and certificate
    :return: The path to the cert and key files on the manager
    """
    if isinstance(owner, str):
        owner = pwd.getpwnam(owner).pw_uid
    if isinstance(group, str):
        group = grp.getgrnam(group).gr_gid

    names = set()
    for addr in itertools.chain(ips, [cn]):
        if parsed_ip := network.parse_ip(addr):
            names.add(x509.IPAddress(parsed_ip))
            # don't break here: still add the IP as a DNS name:
            # some browsers require that
        names.add(x509.DNSName(addr))

    logger.debug(
        'Generating SSL certificate %s and key %s with subjectAltNames: %s',
        cert_path, key_path, names,
    )

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CERT_SIZE,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn),
    ])

    if sign_cert_path and sign_key_path:
        with open(sign_key_path, 'rb') as sign_key_file:
            sign_key = serialization.load_pem_private_key(
                sign_key_file.read(),
                password=(
                    sign_key_password.encode() if sign_key_password else None
                ),
            )
        with open(sign_cert_path, 'rb') as sign_cert_file:
            sign_cert = x509.load_pem_x509_certificate(sign_cert_file.read())
        issuer = sign_cert.subject
    else:
        sign_key = key

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # allow for up to 1 day of time drift, in case other nodes have
        # unsynced clocks
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        # valid for 10 years
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(sign_key, hashes.SHA256())
    )

    with open(key_path, 'wb') as key_file:
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_file.write(key_pem)
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    if os.geteuid() == 0:
        # Don't try to change cert/key ownership if we're not root
        # (this indicates we're running non-sudo-commands such as
        # generate-test-cert)
        os.chown(cert_path, owner, group)
        os.chmod(cert_path, cert_perms)
        os.chown(key_path, owner, group)
        os.chmod(key_path, key_perms)

    logger.debug(
        'Generated SSL certificate: %s and key: %s', cert_path, key_path
    )
    return cert_path, key_path


def generate_internal_ssl_cert(ips, cn):
    cert_path, key_path = _generate_ssl_certificate(
        ips,
        cn,
        const.INTERNAL_CERT_PATH,
        const.INTERNAL_KEY_PATH,
        sign_cert_path=const.CA_CERT_PATH,
        sign_key_path=const.CA_KEY_PATH
    )
    return cert_path, key_path


def generate_external_ssl_cert(
    ips,
    cn,
    sign_cert_path=None,
    sign_key_path=None,
    sign_key_password=None,
):
    return _generate_ssl_certificate(
        ips,
        cn,
        const.EXTERNAL_CERT_PATH,
        const.EXTERNAL_KEY_PATH,
        sign_cert_path=sign_cert_path,
        sign_key_path=sign_key_path,
        sign_key_password=sign_key_password
    )


def generate_ca_cert(cert_path=const.CA_CERT_PATH,
                     key_path=const.CA_KEY_PATH):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CERT_SIZE,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME,
            'Cloudify generated certificate',
        ),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # allow for up to 1 day of time drift, in case other nodes have
        # unsynced clocks
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        # valid for 10 years
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(key_path, 'wb') as key_file:
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_file.write(key_pem)
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))


def remove_key_encryption(src_key_path,
                          dst_key_path,
                          key_password):
    run([
        'openssl', 'rsa',
        '-in', src_key_path,
        '-out', dst_key_path,
        '-passin', u'pass:{0}'.format(key_password).encode('utf-8')
    ])


@argh.arg('--metadata',
          help='File containing the cert metadata. It should be a '
          'JSON file containing an object with the '
          '"hostname" and "networks" fields.')
@argh.arg('--manager-hostname', help='The manager hostname to be stored')
def create_internal_certs(manager_hostname=None,
                          metadata=const.CERT_METADATA_FILE_PATH,
                          verbose=False):
    """
    Recreate Cloudify Manager's internal certificates, based on the manager IP
    and a metadata file input
    """
    setup_console_logger(verbose)
    if not os.path.exists(const.CA_CERT_PATH) or \
            not os.path.exists(const.CA_KEY_PATH):
        raise RuntimeError('Internal CA key and cert mus be available to '
                           'generate internal certs')
    cert_metadata = load_cert_metadata(filename=metadata)
    hostname = manager_hostname or cert_metadata['hostname']

    if cert_metadata.get('manager_addresses'):
        cert_ips = cert_metadata['manager_addresses']
        generate_internal_ssl_cert(
            ips=cert_ips,
            cn=hostname
        )

    if cert_metadata.get('broker_addresses'):
        cert_ips = cert_metadata['broker_addresses']
        _generate_ssl_certificate(
            ips=cert_ips,
            cn=hostname,
            cert_path=BROKER_CERT_LOCATION,
            key_path=BROKER_KEY_LOCATION,
            # We only support ipsetter on nodes with managers, so the fact
            # that this would break if used on a node containing only rmq
            # doesn't matter
            sign_cert_path=const.CA_CERT_PATH,
            sign_key_path=const.CA_KEY_PATH,
        )

    store_cert_metadata(
        hostname,
        filename=metadata
    )


@argh.arg('--private-ip', help="The manager's private IP", required=True)
@argh.arg('--public-ip', help="The manager's public IP", required=True)
@argh.arg('--sign-cert', help="Path to the signing cert "
                              "(self-signed by default)")
@argh.arg('--sign-key', help="Path to the signing cert's key "
                             "(self-signed by default)")
@argh.arg('--sign-key-password', help="Password for the signing key "
                                      "(if provided")
def create_external_certs(private_ip=None,
                          public_ip=None,
                          sign_cert=None,
                          sign_key=None,
                          sign_key_password=None,
                          verbose=False):
    """
    Recreate Cloudify Manager's external certificates, based on the public
    and private IPs
    """
    setup_console_logger(verbose)
    store_cert_metadata(
        private_ip,
        new_managers=[private_ip, public_ip],
        filename=const.EXTERNAL_CERT_METADATA_FILE_PATH,
    )
    # Note: the function has default values for the IP arguments, but they
    # are actually required by argh, so it won't be possible to call this
    # function without them from the CLI
    _generate_ssl_certificate(
        ips=[public_ip, private_ip],
        cn=public_ip,
        cert_path=const.EXTERNAL_CERT_PATH,
        key_path=const.EXTERNAL_KEY_PATH,
        sign_cert_path=sign_cert,
        sign_key_path=sign_key,
        sign_key_password=sign_key_password
    )


def use_supplied_certificates(component_name,
                              logger,
                              cert_destination=None,
                              key_destination=None,
                              ca_destination=None,
                              ca_key_destination=None,
                              owner=CLOUDIFY_USER,
                              group=CLOUDIFY_GROUP,
                              key_perms='440',
                              cert_perms='444',
                              prefix='',
                              just_ca_cert=False,
                              update_config=True,
                              sub_component=None,
                              validate_certs_src_exist=False):
    """Use user-supplied certificates, checking they're not broken.

    Any private key password will be removed, and the config will be
    updated after the certificates are moved to the intended destination.

    At least one of the cert_, key_, or ca_ destination entries must be
    provided.

    Returns True if supplied certificates were used.
    """
    key_path = prefix + 'key_path'
    cert_path = prefix + 'cert_path'
    ca_path = prefix + 'ca_path'
    ca_key_path = prefix + 'ca_key_path'
    key_password = prefix + 'key_password'

    # The ssl_inputs has different names for some of the certificates
    if component_name == SSL_INPUTS:
        if prefix == 'internal_':
            ca_path = 'ca_cert_path'
            ca_key_path = 'ca_key_path'
            key_password = 'ca_key_password'
        elif prefix == 'external_':
            ca_path = prefix + 'ca_cert_path'
            ca_key_path = prefix + 'ca_key_path'

    if just_ca_cert:
        ca_path = cert_path
        key_path = None
        cert_path = None

    config_section = config[component_name]
    section_path = component_name
    if sub_component:
        config_section = config_section[sub_component]
        section_path = section_path + '.' + sub_component

    cert_src, key_src, ca_src, ca_key_src, key_pass = check_certificates(
        config_section,
        section_path,
        cert_path=cert_path,
        key_path=key_path,
        ca_path=ca_path,
        ca_key_path=ca_key_path,
        key_password=key_password,
        require_non_ca_certs=False,
    )

    if not any([cert_src, key_src, ca_src, key_pass]):
        # No certificates supplied, so not using them
        logger.debug('No user-supplied certificates were present.')
        return False

    if validate_certs_src_exist and not (cert_src and key_src):
        logger.debug('The certificate and key were not provided.')
        return False

    # Put the files in the correct place
    logger.info('Ensuring files are in correct locations.')

    if cert_destination and cert_src != cert_destination:
        copy(cert_src, cert_destination, True)
    if key_destination and key_src != key_destination:
        copy(key_src, key_destination, True)
    if ca_destination and ca_src != ca_destination:
        if ca_src:
            copy(ca_src, ca_destination, True)
        else:
            copy(cert_destination, ca_destination, True)
        if ca_key_src and ca_key_destination and \
                ca_key_src != ca_key_destination:
            copy(ca_key_src, ca_key_destination, True)

    if key_pass:
        remove_key_encryption(
            key_destination, key_destination, key_pass
        )

    logger.info('Setting certificate ownership and permissions.')

    for path in cert_destination, key_destination, ca_destination:
        if path:
            chown(owner, group, path)
    # Make key only readable by user and group
    if key_destination:
        chmod(key_perms, key_destination)
    # Make certs readable by anyone
    for path in cert_destination, ca_destination:
        if path:
            chmod(cert_perms, path)

    if update_config:
        logger.info('Updating configured certification locations.')
        if cert_destination:
            config_section[cert_path] = cert_destination
        if key_destination:
            config_section[key_path] = key_destination
        if ca_destination:
            config_section[ca_path] = ca_destination
            # If there was a password, we've now removed it
            config_section[key_password] = ''
        if ca_key_destination:
            config_section[ca_key_path] = ca_key_destination

    # Supplied certificates were used
    return True


def get_and_validate_certs_for_replacement(
        default_cert_location,
        default_key_location,
        default_ca_location,
        default_ca_key_location,
        new_cert_location,
        new_key_location,
        new_ca_location,
        new_ca_key_location):
    """Validates the new certificates for replacement.

    This function validates the new specified certificates for replacement,
    based on the new certificates specified and the current ones. E.g. if
    onlt a new certificate and key were specified, then it will validate them
    with the current CA.
    """

    cert_filename, key_filename = get_cert_and_key_filenames(
        new_cert_location, new_key_location,
        default_cert_location, default_key_location)

    ca_filename = get_ca_filename(new_ca_location, default_ca_location)
    ca_key_filename = None
    if (os.path.exists(new_ca_key_location) and os.path.exists(
            default_ca_key_location)):
        ca_key_filename = new_ca_key_location

    validate_certificates(
        cert_filename, key_filename, ca_filename, ca_key_filename)
    return cert_filename, key_filename, ca_filename, ca_key_filename


def get_cert_and_key_filenames(new_cert_location,
                               new_key_location,
                               default_cert_location,
                               default_key_location):
    if os.path.exists(new_cert_location):
        return new_cert_location, new_key_location

    return default_cert_location, default_key_location


def get_ca_filename(new_ca_location, default_ca_location):
    return (new_ca_location if os.path.exists(new_ca_location)
            else default_ca_location)


def certs_identical(cert_a, cert_b):
    with open(cert_a, 'rb') as cert_a_file:
        cert_a = x509.load_pem_x509_certificate(cert_a_file.read())
    with open(cert_b, 'rb') as cert_b_file:
        cert_b = x509.load_pem_x509_certificate(cert_b_file.read())

    cert_a_modulus = cert_a.public_key().public_numbers().n
    cert_b_modulus = cert_b.public_key().public_numbers().n
    return cert_a_modulus == cert_b_modulus


def clean_certs():
    """Rename the certs on teardown to avoid naming collisions on install."""
    if not os.path.exists(SSL_CERTS_TARGET_DIR):
        # SSL was not configured
        return
    # For the same behaviour as certificates replace
    prefix = datetime.now().strftime('%Y%m%d-%H%M%S_')
    for cert in os.listdir(SSL_CERTS_TARGET_DIR):
        if cert[0] not in string.ascii_letters:
            # This one was renamed on a previous reinstall
            continue
        new_name = prefix + cert
        cert_path = os.path.join(SSL_CERTS_TARGET_DIR, cert)
        new_path = os.path.join(SSL_CERTS_TARGET_DIR, new_name)
        move(cert_path, new_path)


def check_certificates(config_section, section_path,
                       cert_path='cert_path', key_path='key_path',
                       ca_path='ca_path',
                       ca_key_path='ca_key_path',
                       key_password='key_password',
                       require_non_ca_certs=True,
                       ):
    """Check that the provided cert, key, and CA actually match"""
    cert_filename = config_section.get(cert_path)
    key_filename = config_section.get(key_path)

    ca_filename = config_section.get(ca_path)
    ca_key_filename = config_section.get(ca_key_path)
    password = config_section.get(key_password)

    if not cert_filename and not key_filename and require_non_ca_certs:
        failing = []
        if password:
            failing.append('key_password')
        if ca_filename:
            failing.append('ca_path')
        if ca_key_filename:
            failing.append('ca_key_path')
        if failing:
            failing = ' or '.join(failing)
            raise ValidationError(
                'If {failing} was provided, both cert_path and key_path '
                'must be provided in {component}'.format(
                    failing=failing,
                    component=section_path,
                )
            )

    validate_certificates(cert_filename, key_filename, ca_filename,
                          ca_key_filename, password)
    return cert_filename, key_filename, ca_filename, ca_key_filename, password


def validate_certificates(cert_filename=None, key_filename=None,
                          ca_filename=None, ca_key_filename=None,
                          password=None):
    if cert_filename and key_filename:
        check_cert_key_match(cert_filename, key_filename, password)
    elif cert_filename or key_filename:
        raise ValidationError('Either both cert_path and key_path must be '
                              'provided, or neither.')

    if ca_filename:
        check_ssl_file(ca_filename, kind='Cert')
        if cert_filename:
            _check_signed_by(ca_filename, cert_filename)
        if ca_key_filename and os.path.exists(ca_key_filename):
            check_cert_key_match(ca_filename, ca_key_filename, password)


def check_cert_key_match(cert_filename, key_filename, password=None):
    check_ssl_file(key_filename, kind='Key', password=password)
    check_ssl_file(cert_filename, kind='Cert')

    with open(cert_filename, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())

    with open(key_filename, 'rb') as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
        )

    cert_pubkey = cert.public_key()
    key_pubkey = key.public_key()

    if cert_pubkey.public_numbers().n != key_pubkey.public_numbers().n:
        raise ValidationError(
            'Key {key_path} does not match the cert {cert_path}'.format(
                key_path=key_filename,
                cert_path=cert_filename,
            )
        )


def check_ssl_file(filename, kind='Key', password=None):
    """Does the cert/key file exist and is it valid?"""
    if not os.path.isfile(filename):
        raise ValidationError(
            '{0} file {1} does not exist'
            .format(kind, filename))
    if kind == 'Key':
        check_command = ['openssl', 'rsa', '-in', filename, '-check', '-noout']
        if password:
            check_command += [
                '-passin',
                u'pass:{0}'.format(password).encode('utf-8')
            ]
    elif kind == 'Cert':
        check_command = ['openssl', 'x509', '-in', filename, '-noout']
    else:
        raise ValueError('Unknown kind: {0}'.format(kind))
    proc = run(check_command, ignore_failures=True)
    if proc.returncode != 0:
        password_err = ''
        if password:
            password_err = ' (or the provided password is incorrect)'
        raise ValidationError('{0} file {1} is invalid{2}'
                              .format(kind, filename, password_err))


def _check_signed_by(ca_filename, cert_filename):
    with open(ca_filename, 'rb') as ca_file:
        ca_cert = x509.load_pem_x509_certificate(ca_file.read())

    with open(cert_filename, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())

    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise ValidationError(
            'Provided certificate {cert} was not signed by provided '
            'CA {ca}'.format(
                cert=cert_filename,
                ca=ca_filename,
            )
        )
