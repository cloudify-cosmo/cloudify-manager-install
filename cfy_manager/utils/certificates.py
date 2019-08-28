#########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import os
import argh
import json
import socket
import tempfile
from os.path import join
from contextlib import contextmanager

from .common import sudo, remove, chown, copy
from ..components.components_constants import SSL_INPUTS
from ..config import config
from ..constants import SSL_CERTS_TARGET_DIR, CLOUDIFY_USER, CLOUDIFY_GROUP
from ..exceptions import ProcessExecutionError
from .files import write_to_file, write_to_tempfile
from ..components.validations import check_certificates

from ..logger import get_logger
from .. import constants as const

logger = get_logger('Certificates')


def handle_ca_cert(generate_if_missing=True):
    """
    The user might provide both the CA key and the CA cert, or just the
    CA cert, or nothing. It is an error to only provide the CA key.
    If the user provided nothing, we must generate a CA cert+key.
    :return: True if there's a CA key available (either passed or
    generated)
    """
    if os.path.exists(const.CA_CERT_PATH):
        # CA certificate already deployed, no action required
        return os.path.exists(const.CA_KEY_PATH)
    logger.info('Handling CA certificate...')
    cert_deployed, key_deployed = deploy_cert_and_key(
        prefix='ca',
        cert_dst_path=const.CA_CERT_PATH,
        key_dst_path=const.CA_KEY_PATH
    )

    has_ca_key = key_deployed

    if cert_deployed:
        logger.info('Deployed user provided CA cert')
    elif generate_if_missing:
        logger.info('Generating CA certificate...')
        generate_ca_cert()
        has_ca_key = True

    return has_ca_key


def deploy_cert_and_key(prefix, cert_dst_path, key_dst_path):
    if not os.path.exists(SSL_CERTS_TARGET_DIR):
        sudo(['mkdir', '-p', SSL_CERTS_TARGET_DIR])

    cert_path = config[SSL_INPUTS]['{0}_cert_path'.format(prefix)]
    key_path = config[SSL_INPUTS]['{0}_key_path'.format(prefix)]
    key_password = \
        config[SSL_INPUTS].get('{0}_key_password'.format(prefix))

    cert_deployed = False
    key_deployed = False

    if os.path.isfile(cert_path):
        copy(cert_path, cert_dst_path)
        cert_deployed = True
    if os.path.isfile(key_path):
        if key_password:
            remove_key_encryption(key_path,
                                  key_dst_path,
                                  key_password)
        else:
            copy(key_path, key_dst_path)
        key_deployed = True

    return cert_deployed, key_deployed


def _format_ips(ips, cn=None):
    altnames = set(ips)

    if cn:
        altnames.add(cn)

    # Ensure we trust localhost
    altnames.add('127.0.0.1')
    altnames.add('localhost')

    subject_altdns = [
        'DNS:{name}'.format(name=name)
        for name in altnames
    ]
    subject_altips = []
    for name in altnames:
        ip_address = False
        try:
            socket.inet_pton(socket.AF_INET, name)
            ip_address = True
        except socket.error:
            # Not IPv4
            pass
        try:
            socket.inet_pton(socket.AF_INET6, name)
            ip_address = True
        except socket.error:
            # Not IPv6
            pass
        if ip_address:
            subject_altips.append('IP:{name}'.format(name=name))

    cert_metadata = ','.join([
        ','.join(subject_altdns),
        ','.join(subject_altips),
    ])
    return cert_metadata


def store_cert_metadata(private_ip=None,
                        new_brokers=None,
                        new_managers=None,
                        new_networks=None,
                        filename=const.CERT_METADATA_FILE_PATH,
                        owner=const.CLOUDIFY_USER,
                        group=const.CLOUDIFY_GROUP):
    metadata = load_cert_metadata()
    if private_ip:
        metadata['hostname'] = private_ip
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
    write_to_file(metadata, filename, json_dump=True)
    chown(owner, group, filename)


def load_cert_metadata(filename=const.CERT_METADATA_FILE_PATH):
    try:
        # Don't use open because file permissions may cause us to load
        # nothing then stomp the contents if we do
        return json.loads(sudo(['cat', filename]).aggr_stdout)
    except ProcessExecutionError:
        return {}


CSR_CONFIG_TEMPLATE = """
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ext
[ req_distinguished_name ]
commonName = _common_name # ignored, _default is used instead
commonName_default = {cn}
[ v3_ext ]
basicConstraints=CA:false
authorityKeyIdentifier=keyid:true
subjectKeyIdentifier=hash
subjectAltName={metadata}
"""

CA_CONFIG = """
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ext
[ req_distinguished_name ]
commonName = _common_name # ignored, _default is used instead
commonName_default = Cloudify generated certificate
[ v3_ext ]
basicConstraints=CA:true
subjectKeyIdentifier=hash
"""


@contextmanager
def _csr_config(cn, metadata):
    """Prepare a config file for creating a ssl CSR.

    :param cn: the subject commonName
    :param metadata: string to use as the subjectAltName, should be formatted
                     like "IP:1.2.3.4,DNS:www.com"
    """
    csr_config = CSR_CONFIG_TEMPLATE.format(cn=cn, metadata=metadata)
    temp_config_path = write_to_tempfile(csr_config)

    try:
        yield temp_config_path
    finally:
        remove(temp_config_path)


@contextmanager
def _ca_config():
    temp_config_path = write_to_tempfile(CA_CONFIG)

    try:
        yield temp_config_path
    finally:
        remove(temp_config_path)


def _generate_ssl_certificate(ips,
                              cn,
                              cert_path,
                              key_path,
                              sign_cert=None,
                              sign_key=None,
                              sign_key_password=None):
    """Generate a public SSL certificate and a private SSL key

    :param ips: the ips (or names) to be used for subjectAltNames
    :type ips: List[str]
    :param cn: the subject commonName for the new certificate
    :type cn: str
    :param cert_path: path to save the new certificate to
    :type cert_path: str
    :param key_path: path to save the key for the new certificate to
    :type key_path: str
    :param sign_cert: path to the signing cert (self-signed by default)
    :type sign_cert: str
    :param sign_key: path to the signing cert's key (self-signed by default)
    :type sign_key: str
    :return: The path to the cert and key files on the manager
    """
    # Remove duplicates from ips and ensure CN is in SANs
    subject_altnames = _format_ips(ips, cn)
    logger.debug(
        'Generating SSL certificate {0} and key {1} with subjectAltNames: {2}'
        .format(cert_path, key_path, subject_altnames)
    )

    csr_path = '{0}.csr'.format(cert_path)

    with _csr_config(cn, subject_altnames) as conf_path:
        sudo([
            'openssl', 'req',
            '-newkey', 'rsa:2048',
            '-nodes',
            '-batch',
            '-sha256',
            '-config', conf_path,
            '-out', csr_path,
            '-keyout', key_path,
        ])
        x509_command = [
            'openssl', 'x509',
            '-days', '3650',
            '-sha256',
            '-req', '-in', csr_path,
            '-out', cert_path,
            '-extensions', 'v3_ext',
            '-extfile', conf_path
        ]

        if sign_cert and sign_key:
            x509_command += [
                '-CA', sign_cert,
                '-CAkey', sign_key,
                '-CAcreateserial'
            ]
            if sign_key_password:
                x509_command += [
                    '-passin', 'pass:{0}'.format(sign_key_password)
                ]
        else:
            x509_command += [
                '-signkey', key_path
            ]
        sudo(x509_command)
        remove(csr_path)

    logger.debug('Generated SSL certificate: {0} and key: {1}'.format(
        cert_path, key_path
    ))
    return cert_path, key_path


def generate_internal_ssl_cert(ips, cn):
    cert_path, key_path = _generate_ssl_certificate(
        ips,
        cn,
        const.INTERNAL_CERT_PATH,
        const.INTERNAL_KEY_PATH,
        sign_cert=const.CA_CERT_PATH,
        sign_key=const.CA_KEY_PATH
    )
    return cert_path, key_path


def generate_external_ssl_cert(ips, cn, sign_cert=None, sign_key=None,
                               sign_key_password=None):
    return _generate_ssl_certificate(
        ips,
        cn,
        const.EXTERNAL_CERT_PATH,
        const.EXTERNAL_KEY_PATH,
        sign_cert=sign_cert,
        sign_key=sign_key,
        sign_key_password=sign_key_password
    )


def generate_ca_cert(cert_path=const.CA_CERT_PATH,
                     key_path=const.CA_KEY_PATH):
    with _ca_config() as conf_path:
        sudo([
            'openssl', 'req',
            '-x509',
            '-nodes',
            '-newkey', 'rsa:2048',
            '-days', '3650',
            '-batch',
            '-out', cert_path,
            '-keyout', key_path,
            '-config', conf_path,
        ])


def remove_key_encryption(src_key_path,
                          dst_key_path,
                          key_password):
    sudo([
        'openssl', 'rsa',
        '-in', src_key_path,
        '-out', dst_key_path,
        '-passin', 'pass:' + key_password
    ])


@argh.arg('--metadata',
          help='File containing the cert metadata. It should be a '
          'JSON file containing an object with the '
          '"hostname" and "networks" fields.')
@argh.arg('--manager-hostname', help='The manager hostname to be stored')
def create_internal_certs(manager_hostname=None,
                          metadata=const.CERT_METADATA_FILE_PATH):
    """
    Recreate Cloudify Manager's internal certificates, based on the manager IP
    and a metadata file input
    """
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
            cert_path='/etc/cloudify/ssl/rabbitmq_cert.pem',
            key_path='/etc/cloudify/ssl/rabbitmq_key.pem',
            # We only support ipsetter on nodes with managers, so the fact
            # that this would break if used on a node containing only rmq
            # doesn't matter
            sign_cert=const.CA_CERT_PATH,
            sign_key=const.CA_KEY_PATH,
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
                          sign_key_password=None):
    """
    Recreate Cloudify Manager's external certificates, based on the public
    and private IPs
    """
    # Note: the function has default values for the IP arguments, but they
    # are actually required by argh, so it won't be possible to call this
    # function without them from the CLI
    _generate_ssl_certificate(
        ips=[public_ip, private_ip],
        cn=public_ip,
        cert_path=const.EXTERNAL_CERT_PATH,
        key_path=const.EXTERNAL_KEY_PATH,
        sign_cert=sign_cert,
        sign_key=sign_key,
        sign_key_password=sign_key_password
    )


def use_supplied_certificates(component_name,
                              logger,
                              cert_destination=None,
                              key_destination=None,
                              ca_destination=None,
                              owner=CLOUDIFY_USER,
                              group=CLOUDIFY_GROUP,
                              key_perms='440',
                              cert_perms='444',
                              cert_prefix='cert_',
                              key_prefix='key_',
                              ca_prefix='ca_'):
    """Use user-supplied certificates, checking they're not broken.

    Any private key password will be removed, and the config will be
    updated after the certificates are moved to the intended destination.

    At least one of the cert_, key_, or ca_ destination entries must be
    provided.

    Returns True if supplied certificates were used.
    """
    cert_src, key_src, ca_src, key_pass = check_certificates(
        component_name,
        cert_path=cert_prefix + 'path',
        key_path=key_prefix + 'path',
        ca_path=ca_prefix + 'path',
        require_non_ca_certs=False,
    )

    if not any([cert_src, key_src, ca_src, key_pass]):
        # No certificates supplied, so not using them
        logger.debug('No user-supplied certificates were present.')
        return False

    # Put the files in the correct place
    logger.info('Ensuring files are in correct locations.')

    if cert_destination and cert_src != cert_destination:
        copy(cert_src, cert_destination)
    if key_destination and key_src != key_destination:
        copy(key_src, key_destination)
    if ca_destination and ca_src != ca_destination:
        if ca_src:
            copy(ca_src, ca_destination)
        else:
            copy(cert_destination, ca_destination)

    if key_pass:
        remove_key_encryption(
            ca_destination, ca_destination, key_pass
        )

    logger.info('Setting certificate ownership and permissions.')

    for path in cert_destination, key_destination, ca_destination:
        if path:
            sudo(['chown', '{owner}.{group}'.format(owner=owner, group=group),
                  path])
    # Make key only readable by user and group
    if key_destination:
        sudo(['chmod', key_perms, key_destination])
    # Make certs readable by anyone
    for path in cert_destination, ca_destination:
        if path:
            sudo(['chmod', cert_perms, path])

    logger.info('Updating configured certification locations.')
    if cert_destination:
        config[component_name]['cert_path'] = cert_destination
    if key_destination:
        config[component_name]['key_path'] = key_destination
    if ca_destination:
        config[component_name]['ca_path'] = ca_destination
        # If there was a password, we've now removed it
        config[component_name]['key_password'] = ''

    # Supplied certificates were used
    return True
