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
from contextlib import contextmanager

from .common import sudo, remove, chown, copy
from ..components.components_constants import SSL_INPUTS
from ..config import config
from ..constants import SSL_CERTS_TARGET_DIR
from .files import write_to_file, write_to_tempfile

from ..logger import get_logger
from .. import constants as const

logger = get_logger('Certificates')


def handle_ca_cert():
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
    else:
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


def _format_ips(ips):
    altnames = set(ips)

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


def store_cert_metadata(networks,
                        component,
                        filename=const.CERT_METADATA_FILE_PATH,
                        owner=const.CLOUDIFY_USER,
                        group=const.CLOUDIFY_GROUP):
    metadata = load_cert_metadata()
    for network_name, ip in networks.items():
        network = metadata.get(network_name) or {}
        network[component] = ip
        metadata[network_name] = networks
    write_to_file(metadata, filename, json_dump=True)
    chown(owner, group, filename)


def load_cert_metadata(filename=const.CERT_METADATA_FILE_PATH):
    try:
        with open(filename) as f:
            return json.load(f)
    except IOError:
        return {}


CSR_CONFIG_TEMPLATE = """
[req]
distinguished_name = req_distinguished_name
req_extensions = server_req_extensions
[ server_req_extensions ]
subjectAltName={metadata}
[ req_distinguished_name ]
commonName = _common_name # ignored, _default is used instead
commonName_default = {cn}
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
    # Remove duplicates from ips
    subject_altnames = _format_ips(ips)
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
            '-extensions', 'server_req_extensions',
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


def generate_ca_cert():
    sudo([
        'openssl', 'req',
        '-x509',
        '-nodes',
        '-newkey', 'rsa:2048',
        '-days', '3650',
        '-batch',
        '-out', const.CA_CERT_PATH,
        '-keyout', const.CA_KEY_PATH
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
          '"internal_rest_host" and "networks" fields.')
@argh.arg('--manager-ip', help='The IP of this machine on the default network')
def create_internal_certs(manager_ip=None,
                          metadata=const.CERT_METADATA_FILE_PATH):
    """
    Recreate Cloudify Manager's internal certificates, based on the manager IP
    and a metadata file input
    """
    if not os.path.exists(const.CA_CERT_PATH) or \
            not os.path.exists(const.CA_KEY_PATH):
        raise RuntimeError('Internal CA key and cert mus be available to '
                           'generate internal certs')
    if manager_ip:
        store_cert_metadata({'default': manager_ip}, component='nginx')
        store_cert_metadata({'default': manager_ip}, component='rabbitmq')
    cert_metadata = load_cert_metadata(filename=metadata)

    components = {
        'rabbitmq': {
            'key': const.RABBITMQ_KEY_PATH,
            'cert': const.RABBITMQ_CERT_PATH
        },
        'nginx': {
            'key': const.INTERNAL_KEY_PATH,
            'cert': const.INTERNAL_CERT_PATH
        }
    }

    for component, paths in components.items():
        cert_ips = [network.get(component) for network in cert_metadata]
        if not cert_ips:
            continue
        default = cert_metadata['default'].get(component) or cert_ips[0]

        _generate_ssl_certificate(
            cert_ips,
            default,
            paths['cert'],
            paths['key'],
            sign_cert=const.CA_CERT_PATH,
            sign_key=const.CA_KEY_PATH
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
