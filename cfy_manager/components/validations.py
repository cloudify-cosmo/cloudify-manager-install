import os
import re
import distro
import netifaces
from getpass import getuser
from collections import namedtuple
from ipaddress import ip_address
from distutils.version import LooseVersion

from cfy_manager.utils.common import service_is_in_config
from ..components_constants import (
    PRIVATE_IP,
    PUBLIC_IP,
    SECURITY,
    VALIDATIONS,
    SKIP_VALIDATIONS,
    SSL_INPUTS,
    SSL_ENABLED,
    SSL_CLIENT_VERIFICATION,
    ENABLE_REMOTE_CONNECTIONS,
    POSTGRES_PASSWORD,
    SERVER_PASSWORD
)
from ..service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
    DATABASE_SERVICE,
    MANAGER_SERVICE
)

from ..config import config
from ..logger import get_logger
from ..constants import USER_CONFIG_PATH
from ..exceptions import ValidationError

from ..utils.common import run
from ..utils.certificates import (
    check_cert_key_match,
    check_certificates,
    check_ssl_file,
    get_cert_cn,
)
from ..utils.network import is_ipv6

logger = get_logger(VALIDATIONS)

_errors = []


def _get_os_distro():
    return distro.id().lower(), distro.version().split('.')[0]


def _get_host_total_memory():
    """
    MemTotal:        7854400 kB
    MemFree:         1811840 kB
    MemAvailable:    3250176 kB
    Buffers:          171164 kB
    Cached:          1558216 kB
    SwapCached:       119180 kB
    """
    with open('/proc/meminfo') as memfile:
        memory = memfile.read()
    for attribute in memory.splitlines():
        if attribute.lower().startswith('memtotal'):
            return int(attribute.split(':')[1].strip().split(' ')[0]) // 1024


def _get_available_host_disk_space():
    """Available space in GB on the filesystem containing /opt"""
    result = os.statvfs('/opt')
    bytes_available = result.f_bavail * result.f_bsize
    return bytes_available // (1024 * 1024 * 1024)


def _validate_supported_distros():
    logger.info('Validating supported distributions...')
    distro, version = _get_os_distro()
    supported_distros = config[VALIDATIONS]['supported_distros']

    # `platform` lib. has "redhat"; since 7.0 we use `distro` that has "rhel"
    if 'redhat' in supported_distros:
        supported_distros.append('rhel')

    supported_distro_versions = \
        config[VALIDATIONS]['supported_distro_versions']
    if distro not in supported_distros:
        _errors.append(
            'Cloudify manager does not support the current distro (`{0}`), '
            'supported distros are: {1}'.format(distro, supported_distros)
        )
    if version not in supported_distro_versions:
        _errors.append(
            'Cloudify manager does not support the current distro version '
            '(`{0}`), supported versions are: {1}'.format(
                version, supported_distro_versions
            )
        )


def _validate_ip(ip_to_validate, check_local_interfaces=False):
    """
    Validate the IP address given is valid.

    :param ip_to_validate: IP address to validate
    :param check_local_interfaces: If true, will check local interfaces
           associated with the IP address
    :return: Will break in case of error
    """
    logger.info('Validating IP address...')

    try:
        ip_address(ip_to_validate)
    except ValueError:
        logger.debug('Failed creating an IP address from "{}"'.format(
            ip_to_validate), exc_info=True)
        logger.info('Provided value ({}) is not an IP address; '
                    'skipping'.format(ip_to_validate))
        return

    if check_local_interfaces:
        all_addresses = set()
        found = False
        for interface in netifaces.interfaces():
            int_addresses = netifaces.ifaddresses(interface)
            if not int_addresses:
                logger.debug(
                    'Could not find any addresses for interface {0}'.format(
                        interface))
                continue
            inet_addresses = int_addresses.get(
                netifaces.AF_INET6 if is_ipv6(ip_to_validate)
                else netifaces.AF_INET
            )
            if not inet_addresses:
                logger.debug('No AF_INET addresses found for interface {0}'
                             .format(interface))
                continue
            for inet_addr in inet_addresses:
                addr = inet_addr.get('addr')
                if not addr:
                    logger.debug('No addr found for {0}'.format(inet_addr))
                    continue
                if addr == ip_to_validate:
                    found = True
                    break
                all_addresses.add(addr)
            if found:
                break

        if not found:
            _errors.append(
                "The provided private IP ({ip}) is not associated with any "
                "INET-type address available on this machine (available "
                "INET-type addresses: {addresses}). This will cause "
                "installation to fail. If you are certain that this IP address"
                " should be used, please set the '{param}' parameter to "
                "'true'".format(
                    ip=ip_to_validate,
                    addresses=', '.join(all_addresses),
                    param=SKIP_VALIDATIONS))


def _validate_sufficient_memory():
    logger.info('Validating memory requirement...')
    current_memory = _get_host_total_memory()
    required_memory = \
        config[VALIDATIONS]['minimum_required_total_physical_memory_in_mb']
    if current_memory < required_memory:
        _errors.append(
            'The provided host does not have enough memory to run '
            'Cloudify Manager (Current: {0}MB, Required: {1}MB).'.format(
                current_memory, required_memory)
        )


def _validate_sufficient_disk_space():
    logger.info('Validating disk space requirement...')
    available_disk_space_in_gb = _get_available_host_disk_space()
    required_disk_space = \
        config[VALIDATIONS]['minimum_required_available_disk_space_in_gb']

    if available_disk_space_in_gb < required_disk_space:
        _errors.append(
            'The provided host does not have enough disk space to run '
            'Cloudify Manager (Current: {0}GB, Required: {1}GB).'.format(
                available_disk_space_in_gb, required_disk_space)
        )


def _validate_openssl_version():
    logger.info('Validating OpenSSL version...')
    required_version = '1.0.2'

    try:
        output = run(['openssl', 'version']).aggr_stdout
    except OSError as e:
        _errors.append(
            'Cloudify Manager requires OpenSSL {0}, Error: {1}'.format(
                required_version, e
            )
        )
        return

    # The output should look like: "LibreSSL 2.2.7" or "OpenSSL 1.0.2k-fips"
    version = output.split()[1]
    if LooseVersion(version) < LooseVersion(required_version):
        _errors.append(
            'Cloudify Manager requires OpenSSL {0}, current version: {1}'
            ''.format(required_version, version)
        )


def _validate_inputs():
    Input = namedtuple('Input', 'key string flag')
    required_inputs = [
        Input(key=PRIVATE_IP, flag='--private-ip', string='Private IP'),
        Input(key=PUBLIC_IP, flag='--public-ip', string='Public IP')
    ]
    for inp in required_inputs:
        input_value = config[MANAGER].get(inp.key)
        if not input_value:
            raise ValidationError(
                '{string} not set in the config.\n'
                'Possible solutions are:\n'
                '1. Set the `{key}` key in {config_path}\n'
                '2. Use the `{flag}` flag when running '
                '`cfy_manager install/configure`'.format(
                    string=inp.string,
                    key=inp.key,
                    config_path=USER_CONFIG_PATH,
                    flag=inp.flag
                )
            )


def _validate_env():
    """Check that the process env is as expected by the validations config.

    In the config, validations.expected_env is a dict of envvar names to
    patterns, or to lists of patterns. Check that each envvar's value
    contains that pattern, or in case of a list: all the patterns.
    """
    expected_env = config[VALIDATIONS].get('expected_env') or {}
    mismatch = []
    for envvar, patterns in expected_env.items():
        if not isinstance(patterns, list):
            patterns = [patterns]
        envvar_value = os.environ.get(envvar, '')
        for pattern in patterns:
            if not re.search(pattern, envvar_value):
                mismatch.append((envvar, pattern))
    if mismatch:
        mismatch_message = ', '.join(
            '{0} must match {1}'.format(value, pattern)
            for value, pattern in mismatch
        )
        raise ValidationError(
            'Environment variables mismatch: ' + mismatch_message,
        )


def _validate_user_has_sudo_permissions():
    current_user = getuser()
    logger.info('Validating user `%s` has sudo permissions...', current_user)
    result = run(['/usr/bin/sudo', '--validate'])
    if result.returncode != 0:
        _errors.append(
            "Failed executing 'sudo'. Please ensure that the "
            "current user ({0}) is allowed to execute 'sudo' commands "
            "and impersonate other users using "
            "'sudo -u'. (Error: {1})".format(current_user, result.aggr_stderr)
        )


def validate_dependencies(components):
    logger.info('Validating dependencies...')

    components_str = ', '.join([component.__class__.__name__
                               for component in components])
    logger.debug('The following components are validated: '
                 '{0}'.format(components_str))

    for component in components:
        component.validate_dependencies()


def _check_internal_ca_cert():
    ssl_inputs = config[SSL_INPUTS]
    if ssl_inputs['ca_key_path'] and ssl_inputs['ca_cert_path']:
        check_ssl_file(ssl_inputs['ca_key_path'],
                       password=ssl_inputs['ca_key_password'])
        check_ssl_file(ssl_inputs['ca_cert_path'], kind='Cert')
    elif ssl_inputs['ca_key_path'] and not ssl_inputs['ca_cert_path']:
        raise ValidationError('Internal CA key provided, but the internal '
                              'CA cert was not')
    elif ssl_inputs['ca_cert_path'] and not ssl_inputs['ca_key_path']:
        if not ssl_inputs['internal_cert_path'] \
                or not ssl_inputs['internal_key_path']:
            raise ValidationError('If ca_cert_path was provided, but '
                                  'ca_key_path was not provided, both '
                                  'internal_cert_path and internal_key_path '
                                  'must be provided.')
    elif ssl_inputs['ca_key_password']:
        raise ValidationError('If ca_key_password was provided, both '
                              'ca_cert_path and ca_key_path must be '
                              'provided.')


def _validate_ssl_and_external_certificates_match():
    logger.info('Validating ssl_enabled and external certificate...')
    external_certificate = config[SSL_INPUTS]['external_cert_path']
    if external_certificate and not config[MANAGER][SECURITY]['ssl_enabled']:
        raise ValidationError("`ssl_enabled` was set to false and an external"
                              " certificate was given. If you wish to supply "
                              "an external certificate, please set "
                              "`ssl_enabled` to true.")


def _is_cert_self_signed(cert_file):
    result = run(['openssl', 'verify', '-CAfile', cert_file, cert_file],
                 ignore_failures=True)
    return result.returncode == 0


def _validate_external_ssl_cert_and_ca():
    logger.info('Validating that the external SSL certificate matches the CA')
    external_certificate = config[SSL_INPUTS]['external_cert_path']
    external_ca = config[SSL_INPUTS]['external_ca_cert_path']
    err_msg = 'If the external certificate is signed by a CA, the ' \
              '`external_ca_cert_path` must be provided'
    if external_certificate:
        if not _is_cert_self_signed(external_certificate):
            if not external_ca:
                raise ValidationError(err_msg)


def _validate_cert_inputs():
    _check_internal_ca_cert()
    for ssl_input in (
        'internal',
        'postgresql_server',
        'postgresql_client',
        'external'
    ):
        cert_path = '{0}_cert_path'.format(ssl_input)
        key_path = '{0}_key_path'.format(ssl_input)
        ca_path = '{0}_ca_path'.format(ssl_input)
        ca_key_path = '{0}_ca_key_path'.format(ssl_input)
        key_password = '{0}_key_password'.format(ssl_input)
        # These should all be moved to their respective components- see Rabbit
        check_certificates(
            config[SSL_INPUTS],
            SSL_INPUTS,
            cert_path=cert_path,
            key_path=key_path,
            ca_path=ca_path,
            ca_key_path=ca_key_path,
            key_password=key_password,
        )
    if config[SSL_INPUTS].get('external_ca_cert_path'):
        if config[SSL_INPUTS].get('external_ca_key_path'):
            check_cert_key_match(
                config[SSL_INPUTS]['external_ca_cert_path'],
                config[SSL_INPUTS]['external_ca_key_path'],
                config[SSL_INPUTS].get('external_ca_key_password')
            )
        else:
            check_ssl_file(config[SSL_INPUTS]['external_ca_cert_path'],
                           kind='Cert')
    if config[POSTGRESQL_SERVER]['ca_path']:
        check_ssl_file(config[POSTGRESQL_SERVER]['ca_path'],
                       kind='Cert')
        config[POSTGRESQL_CLIENT]['ca_path'] = \
            config[POSTGRESQL_SERVER]['ca_path']
    elif config[POSTGRESQL_CLIENT]['ca_path']:
        check_ssl_file(config[POSTGRESQL_CLIENT]['ca_path'],
                       kind='Cert')


def _validate_postgres_server_and_cloudify_input_difference():
    pg_conf = config[POSTGRESQL_CLIENT]
    condition = [
        pg_conf['server_username'] == pg_conf['cloudify_username'],
        pg_conf['server_db_name'] == pg_conf['cloudify_db_name']
    ]
    if any(condition):
        raise ValidationError('The server_username and server_db_name values '
                              'must be different than the cloudify_username '
                              'and cloudify_db_name values respectively')


def _validate_postgres_azure_configuration():
    condition = [
        '@' in entry for entry in [
            config[POSTGRESQL_CLIENT]['server_username'],
            config[POSTGRESQL_CLIENT]['cloudify_username']]
    ]
    if any(condition) and not all(condition):
        raise ValidationError(
            'It appears you are trying to connect to Azure DBaaS.\n'
            'When doing so, make sure both "server_username" and "username" '
            'under "postgresql_client" are set with the relevant Azure domain'
        )


def _validate_postgres_cluster_configuration():
    condition = [
        'ip' in node for node in
        config[POSTGRESQL_SERVER]['cluster']['nodes'].values()
    ]
    if not all(condition):
        raise ValidationError(
            'When using a Postgres Cluster ip must be set for each DB node'
        )


def _validate_postgres_inputs():
    """
    Validating that an external DB will always listen to remote connections
    and, that a postgres password is set - needed for remote connections
    """
    db_service_in_config = service_is_in_config(DATABASE_SERVICE)
    manager_service_in_config = service_is_in_config(MANAGER_SERVICE)
    if db_service_in_config and manager_service_in_config:
        if config[POSTGRESQL_CLIENT]['host'] not in ('localhost', '127.0.0.1'):
            raise ValidationError('Cannot install database_service when '
                                  'connecting to an external database')
        elif config[POSTGRESQL_SERVER]['cluster']['nodes']:
            raise ValidationError('Cannot install database_service when '
                                  'connecting to a Postgres Cluster')
    if db_service_in_config and not manager_service_in_config:
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            if not config[POSTGRESQL_SERVER][POSTGRES_PASSWORD]:
                raise ValidationError('When using an external database with '
                                      'a Postgres Cluster, postgres_password '
                                      'must be set to a non-empty value')

        elif config[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS] and \
            not config[POSTGRESQL_SERVER][POSTGRES_PASSWORD] \
            or \
            not config[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS] and \
                config[POSTGRESQL_SERVER][POSTGRES_PASSWORD]:
            raise ValidationError('When using an external database, both '
                                  'enable_remote_connections and '
                                  'postgres_password must be set')

    if manager_service_in_config:
        if config[POSTGRESQL_SERVER][SSL_CLIENT_VERIFICATION]:
            required_certs, good_certs = _has_required_client_certs()
            if not good_certs:
                if 'upgrade' in config:
                    _disable_db_client_certs()
                    return
                certs = ', '.join(required_certs)
                raise ValidationError(
                    'When using ssl_client_verification, the following certs '
                    f'must be provided in the config under {SSL_INPUTS}: '
                    f'{certs}'
                )

    if manager_service_in_config and not db_service_in_config:
        postgres_host = config[POSTGRESQL_CLIENT]['host'].rsplit(':', 1)[0]
        if postgres_host in ('localhost', '127.0.0.1', '::1') and \
                not config[POSTGRESQL_CLIENT][SERVER_PASSWORD]:
            raise ValidationError('When using an external database, '
                                  'postgres_password must be set')
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            _validate_postgres_cluster_configuration()

    if config[POSTGRESQL_SERVER][SSL_CLIENT_VERIFICATION]:
        if not config[POSTGRESQL_SERVER]['ssl_only_connections']:
            raise ValidationError(
                'When using ssl_client_verification, ssl_only_connections '
                'must be enabled to ensure client verification takes place.'
            )
    _validate_postgres_azure_configuration()
    _validate_postgres_server_and_cloudify_input_difference()


def _has_required_client_certs():
    required_certs = [
        'postgresql_client_cert_path',
        'postgresql_client_key_path',
    ]
    if 'upgrade' not in config:
        # These are only absolutely required for bootstrap
        required_certs.extend([
            'postgresql_superuser_client_cert_path',
            'postgresql_superuser_client_key_path',
        ])
    ssl_inputs = config[SSL_INPUTS]
    return required_certs, all(ssl_inputs[entry] for entry in required_certs)


def _validate_postgres_ssl_certificates_provided():
    error_msg = 'If Postgresql requires SSL communication {0} ' \
                'for Postgresql must be provided in ' \
                'config.yaml in {1}'
    if service_is_in_config(DATABASE_SERVICE):
        if not (config['postgresql_server']['cert_path'] and
                config['postgresql_server']['key_path'] and
                config['postgresql_server']['ca_path']):
            if config[POSTGRESQL_SERVER][SSL_ENABLED] or \
               config[POSTGRESQL_SERVER]['cluster']['nodes']:
                raise ValidationError(error_msg.format(
                    'a CA certificate, a certificate and a key',
                    'postgresql_server.cert_path, '
                    'postgresql_server.key_path, '
                    'and postgresql_server.ca_path'))
    elif service_is_in_config(MANAGER_SERVICE):
        if not config['postgresql_server']['ca_path'] and not \
                config['postgresql_client']['ca_path']:
            # Do not allow external postgres without SSL
            raise ValidationError(
                error_msg.format('a CA certificate',
                                 'postgresql_server.ca_path or '
                                 'postgresql_client.ca_path')
            )
        if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
            required_certs, good_certs = _has_required_client_certs()
            good_certs = (
                good_certs
                and bool(config[POSTGRESQL_SERVER]['ca_path'])
            )
            if not good_certs:
                if 'upgrade' in config:
                    _disable_db_client_certs()
                    return
                certs = ', '.join(
                    f'ssl_inputs.{cert}'
                    for cert in required_certs
                )
                raise ValidationError(error_msg.format(
                    'with client verification, a CA certificate, '
                    'a certificate and a key ',
                    f'{certs}, '
                    'and postgresql_server.ca_path'))


def _disable_db_client_certs():
    logger.warning(
        'Unsuitable client certs for upgrade. '
        'This is likely caused by changes in postgres '
        'client cert handling, so client certs will be '
        'disabled.'
    )
    config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION] = False
    config[POSTGRESQL_SERVER][SSL_CLIENT_VERIFICATION] = False


def _validate_external_postgres():
    pg_conf = config[POSTGRESQL_SERVER]

    if (
        service_is_in_config(DATABASE_SERVICE)
        and service_is_in_config(MANAGER_SERVICE)
    ):
        if pg_conf['cluster']['nodes']:
            raise ValidationError('Postgres cluster nodes cannot be '
                                  'installed on manager nodes.')
        else:
            # Local DB, no need to conduct external checks
            return

    if service_is_in_config(DATABASE_SERVICE):
        if pg_conf['cluster']['nodes']:
            problems = []

            if len(pg_conf['cluster']['nodes']) < 2:
                problems.append('There must be at least 2 DB cluster nodes.')
            elif len(pg_conf['cluster']['nodes']) < 3:
                logger.warning(
                    'At least 3 nodes are recommended for DB clusters.'
                )

            etcd_conf = pg_conf['cluster']['etcd']
            if not all(
                etcd_conf.get(entry) for entry in
                ('cluster_token', 'root_password', 'patroni_password')
            ):
                problems.append(
                    'Etcd cluster token and passwords must be set.'
                )

            patroni_conf = pg_conf['cluster']['patroni']
            if not all(patroni_conf.get(entry) for entry in
                       ('rest_user', 'rest_password')):
                problems.append(
                    'Patroni rest username and password must be set.'
                )

            if not pg_conf['cluster']['postgres']['replicator_password']:
                problems.append('Postgres replicator password must be set.')

            if problems:
                raise ValidationError(
                    'Problems detected in postgresql_server.cluster '
                    'configuration: {problems}'.format(
                        problems=' '.join(problems),
                    )
                )


def _validate_postgres_client_certs():
    if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
        ssl_props = config[SSL_INPUTS]
        client_cert_cn = get_cert_cn(ssl_props['postgresql_client_cert_path'])
        if client_cert_cn != 'cloudify':
            if 'upgrade' in config:
                config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION] = False
                return
            else:
                raise ValidationError(
                    'Client certificates require their CN to be set to '
                    '"cloudify" (without quotes). Provided client cert '
                    f'has CN: {client_cert_cn}'
                )

        # It is acceptable not to have superuser cert on upgrade,
        # though if we do have it, we'll test t.
        if (
            'upgrade' in config
            and not ssl_props['postgresql_superuser_client_cert_path']
        ):
            return
        client_su_cert_cn = get_cert_cn(
            ssl_props['postgresql_superuser_client_cert_path'])
        client_su_name = config[POSTGRESQL_CLIENT]['server_username']
        if client_su_cert_cn != client_su_name:
            raise ValidationError(
                'Client superuser certificates require their CN to be set to '
                f'"{client_su_name}" (without quotes). Provided client cert '
                f'has CN: {client_su_cert_cn}'
            )


def validate(components, skip_validations=False, only_install=False):
    if not only_install:
        # Inputs always need to be validated, otherwise the install won't work
        _validate_inputs()

    if config[VALIDATIONS][SKIP_VALIDATIONS] or skip_validations:
        logger.info('Skipping validations')
        return

    logger.notice('Validating local machine...')

    if not only_install:
        _validate_ip(config[MANAGER][PRIVATE_IP], check_local_interfaces=True)
        _validate_ip(ip_to_validate=config[MANAGER][PUBLIC_IP])
        if config[POSTGRESQL_CLIENT]['host'] not in ('localhost', '127.0.0.1'):
            _validate_ip(ip_to_validate=config[POSTGRESQL_CLIENT]['host'])
        _validate_env()
        _validate_sufficient_memory()
        _validate_postgres_inputs()
        _validate_external_postgres()
        _validate_postgres_ssl_certificates_provided()
        _validate_postgres_client_certs()
        _validate_ssl_and_external_certificates_match()
        _validate_external_ssl_cert_and_ca()
        _validate_cert_inputs()

    _validate_supported_distros()
    _validate_openssl_version()
    _validate_user_has_sudo_permissions()
    _validate_sufficient_disk_space()

    if _errors:
        printable_error = 'Validation error(s):\n' \
                          '{0}'.format('\n'.join(_errors))
        raise ValidationError(printable_error)
    logger.notice('All validations passed successfully!')
