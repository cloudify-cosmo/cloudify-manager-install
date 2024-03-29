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
import ipaddress
import os
import socket
import base64
from time import sleep
from tempfile import mkstemp
from ipaddress import ip_address
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..exceptions import NetworkError
from ..service_names import MANAGER

from .common import run
from ..config import config
from ..logger import get_logger

logger = get_logger('Network')


def parse_ip(ip):
    """Parse the string ip, and return an IPAddress or None"""
    # ip should be unicode, coming from yaml, but in python 2
    # it can unfortunately be bytes depending on the actual value
    if isinstance(ip, bytes):
        ip = ip.decode('utf-8')
    try:
        return ip_address(ip)
    except ValueError:
        return None


def is_url(url):
    return urlparse(url).scheme != ''


def is_port_open(port, host='localhost'):
    """Try to connect to (host, port), return if the port was listening."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return sock.connect_ex((host, port)) == 0


def wait_for_port(port, host='localhost'):
    """Helper function to wait for a port to open before continuing"""
    counter = 1

    logger.info('Waiting for {0}:{1} to become available...'.format(
        host, port))

    for tries in range(24):
        if not is_port_open(port, host=host):
            logger.info(
                '{0}:{1} is not available yet, retrying... '
                '({2}/24)'.format(host, port, counter))
            sleep(2)
            counter += 1
            continue
        logger.info('{0}:{1} is open!'.format(host, port))
        return
    raise NetworkError(
        'Failed to connect to {0}:{1}...'.format(host, port)
    )


def curl_download(source, destination=None):
    """Download file using the curl command.

    :param source: Source URL for the file to download
    :typ source: str
    :param destination:
        Path to the directory where the file should be downloaded.
        If none is provided, a temp file will be used
    :type destination: str

    """
    if not destination:
        suffix = '.{0}'.format(source.split('.')[-1])
        fd, destination = mkstemp(suffix=suffix)
        os.close(fd)
        config.add_temp_path_to_clean(destination)

    curl_cmd = [
        'curl',
        '--silent',
        '--show-error',
        '--location', source,
        '--create-dir',
        '--output', destination,
    ]
    logger.info('Downloading: {0} into {1}'.format(source, destination))
    run(curl_cmd)
    return destination


def get_auth_headers():
    security = config[MANAGER]['security']
    username = security['admin_username']
    password = security['admin_password']
    return {
        'Authorization':
            'Basic ' + base64.b64encode(
                '{0}:{1}'.format(username, password).encode('utf-8')
            ).decode('ascii'),
        'tenant': 'default_tenant'
    }


def check_http_response(url, **request_kwargs):
    req = Request(url, **request_kwargs)
    try:
        response = urlopen(req)
    except HTTPError as e:
        # HTTPError can also be used as a non-200 response. Pass this
        # through to the predicate function, so it can decide if a
        # non-200 response is fine or not.
        response = e

    return response


def is_ipv6(addr):
    """Verifies if `addr` is a valid IPv6 address."""
    try:
        return bool(ipaddress.IPv6Address(addr))
    except ipaddress.AddressValueError:
        return False


def is_ipv6_link_local(addr):
    """Verifies if `addr` is an ipv6 link local address."""
    try:
        return ipaddress.IPv6Address(addr).is_link_local
    except ipaddress.AddressValueError:
        return False


def ipv6_url_compat(addr):
    """Return URL-compatible version of IPv6 address (or just an address)."""
    if addr and is_ipv6(addr):
        return '[{0}]'.format(addr)
    return addr


def ipv6_url_strip(url_addr):
    """Strip brackets from the URL-compatible version of IPv6 address."""
    if url_addr.startswith('[') and url_addr.endswith(']'):
        return url_addr[1:-1]
    return url_addr


def lo_has_ipv6_addr():
    lo_ip6_addr = run(['/usr/sbin/ip', '-6', 'addr', 'show', 'dev', 'lo'],
                      ignore_failures=True).aggr_stdout
    return 'inet6' in (lo_ip6_addr or '')
