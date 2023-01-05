import socket
from os.path import exists, join
from functools import partial

from retrying import retry

from .files import deploy, remove as remove_file
from .common import (
    chown,
    run,
)

from ..config import config
from .._compat import httplib, xmlrpclib
from ..logger import get_logger
from ..constants import (
    COMPONENTS_DIR,
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ..exceptions import ValidationError

logger = get_logger('Service')

ACTIVE_STATES = ['running', 'active', 'activating']


class UnixSocketHTTPConnection(httplib.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.host)


class UnixSocketTransport(xmlrpclib.Transport, object):
    def __init__(self, path):
        super(UnixSocketTransport, self).__init__()
        self._path = path

    def make_connection(self, host):
        return UnixSocketHTTPConnection(self._path)


class SystemD(object):
    @staticmethod
    def systemctl(
            action,
            service='',
            retries=0,
            ignore_failure=False,
            options=None
    ):
        options = options or []
        systemctl_cmd = ['systemctl', action]
        if service:
            systemctl_cmd.append(service)
        # If options are passed to the systemctl action
        if options:
            systemctl_cmd.extend(options)
        return run(systemctl_cmd, retries=retries,
                   ignore_failures=ignore_failure)

    def configure(self,
                  service_name,
                  user=CLOUDIFY_USER,
                  group=CLOUDIFY_GROUP,
                  external_configure_params=None,
                  config_path='config',
                  src_dir=None,
                  render=True,
                  ignore_failure=False):
        """This configures systemd for a specific service.
        It requires that two files are present for each service one containing
        the environment variables and one containing the systemd config.
        All env files will be named "cloudify-SERVICENAME".
        All systemd config files will be named "cloudify-SERVICENAME.service".
        """
        env_dst = "/etc/sysconfig/{0}".format(service_name)
        srv_dst = "/usr/lib/systemd/system/{0}.service".format(service_name)

        if src_dir is None:
            src_dir = _strip_prefix(service_name)

        service_dir_name = src_dir.replace('-', '_')
        src_dir = join(COMPONENTS_DIR, service_dir_name, config_path)
        env_src = join(src_dir, service_name)
        srv_src = join(src_dir, '{0}.service'.format(service_name))

        if exists(env_src):
            logger.debug('Deploying systemd EnvironmentFile...')
            deploy(env_src, env_dst, render=render,
                   additional_render_context=external_configure_params)
            chown(user, group, env_dst)

        # components that have had their service file moved to a RPM, won't
        # have the file here.
        if exists(srv_src):
            logger.debug('Deploying systemd .service file...')
            deploy(srv_src, srv_dst, render=True,
                   additional_render_context=external_configure_params)

        logger.debug('Enabling systemd .service...')
        self.enable('{0}.service'.format(service_name),
                    ignore_failure=ignore_failure)

    def remove(self, service_name):
        """Stop and disable the service, and then delete its data
        """
        self.stop(service_name, ignore_failure=True)
        self.disable(service_name, ignore_failure=True)
        remove_file(self.get_service_file_path(service_name))
        remove_file(self.get_vars_file_path(service_name))

    @staticmethod
    def get_vars_file_path(service_name):
        """Returns the path to a systemd environment variables file
        for a given service_name. (e.g. /etc/sysconfig/cloudify-rabbitmq)
        """
        return '/etc/sysconfig/{0}'.format(service_name)

    @staticmethod
    def get_service_file_path(service_name):
        """Returns the path to a systemd service file
        for a given service_name.
        (e.g. /usr/lib/systemd/system/cloudify-rabbitmq.service)
        """
        return "/usr/lib/systemd/system/{0}.service".format(service_name)

    def enable(self, service_name, ignore_failure=False):
        logger.debug('Enabling systemd service {0}...'.format(service_name))
        self.systemctl('enable', service_name, ignore_failure=ignore_failure)

    def disable(self, service_name, ignore_failure=False):
        logger.debug('Disabling systemd service {0}...'.format(service_name))
        self.systemctl('disable', service_name, ignore_failure=ignore_failure)

    def start(self, service_name, is_group=False, options=None,
              ignore_failure=False):
        logger.debug('Starting systemd service {0}...'.format(service_name))
        self.systemctl(
            'start',
            service_name,
            ignore_failure=ignore_failure,
            options=options
        )

    def stop(self, service_name, is_group=False, ignore_failure=False):
        logger.debug('Stopping systemd service {0}...'.format(service_name))
        self.systemctl('stop', service_name, ignore_failure=ignore_failure)

    def restart(self, service_name, is_group=False, ignore_failure=False):
        self.systemctl('restart', service_name, ignore_failure=ignore_failure)

    def reload(self, service_name, ignore_failure=False):
        self.systemctl('reload', service_name, ignore_failure=ignore_failure)

    def is_alive(self, service_name, is_group=False):
        result = self.systemctl('status', service_name, ignore_failure=True)
        return result.returncode == 0

    def is_active(self, service_name):
        return self.systemctl(
            'is-active',
            service_name,
            ignore_failure=True
        ).aggr_stdout.strip().lower() in ACTIVE_STATES

    def is_installed(self, service_name):
        if not self.systemctl(
            'is-system-running',
            ignore_failure=True,
        ).aggr_stdout.strip():
            # Any output at all means systemd is running. No output means
            # it isn't. The actual output (if there is any) varies depending
            # on whether any services (at all) failed to start.
            logger.debug('Systemd system is not running, assuming no '
                         'services are installed.')
            return False

        enabled = self.systemctl(
            'is-enabled',
            service_name,
            ignore_failure=True
        ).aggr_stdout.strip()
        # We actually have the servies installed on yum install, but what we
        # care about where we use this function is whether we're using it-
        # and in that case it'll be enabled.
        return enabled.strip().lower() == 'enabled'

    def reread(self):
        return self.systemctl('daemon-reload')


class Supervisord(object):
    def supervisorctl(
            self,
            action,
            service='',
            ignore_failure=False,
            options=None
    ):
        options = options or []
        cmd = [
            'supervisorctl', '-c', '/etc/supervisord.conf', action
        ]
        if service:
            cmd += [service]
        if options:
            cmd.extend(options)
        return run(cmd, ignore_failures=ignore_failure)

    def enable(self, service_name, ignore_failure=False):
        self.supervisorctl(
            'update',
            service_name,
            ignore_failure=ignore_failure
        )

    def disable(self, service_name, ignore_failure=False):
        self.supervisorctl(
            'remove',
            service_name,
            ignore_failure=ignore_failure
        )

    def start(self, service_name, is_group=False, options=None,
              ignore_failure=False):
        self.enable(service_name, ignore_failure=ignore_failure)
        self.supervisorctl(
            'start',
            _supervisord_service_name(service_name, is_group),
            ignore_failure=ignore_failure,
            options=options
        )

    def stop(self, service_name, is_group=False, ignore_failure=False):
        self.enable(service_name, ignore_failure=ignore_failure)
        self.supervisorctl(
            'stop',
            _supervisord_service_name(service_name, is_group),
            ignore_failure=ignore_failure
        )

    def restart(self, service_name, is_group=False, ignore_failure=False):
        self.enable(service_name, ignore_failure=ignore_failure)
        self.supervisorctl(
            'restart',
            _supervisord_service_name(service_name, is_group),
            ignore_failure=ignore_failure
        )

    def reload(self, service_name, ignore_failure=False):
        self.supervisorctl(
            'reread',
            ignore_failure=ignore_failure
        )
        self.enable(service_name, ignore_failure=ignore_failure)

    def is_alive(self, service_name, is_group=False):
        result = self.supervisorctl(
            'status',
            _supervisord_service_name(service_name, is_group),
            ignore_failure=True)
        return result.returncode == 0

    def is_active(self, service_name):
        # Output of `supervisorctl -c /etc/supervisord.conf status SERVICE`
        # is on the following format
        # "SERVICE                          EXITED    Jun 09 09:35 AM"
        # Remove new line and then split the output to get the desired status
        return self.supervisorctl(
            'status', service_name,
            ignore_failure=True
        ).aggr_stdout.strip().split()[1].lower() in ACTIVE_STATES

    def is_installed(self, service_name):
        status = self.supervisorctl(
            'status',
            service_name,
            ignore_failure=True
        ).aggr_stdout.strip()
        return 'ERROR (no such process)' not in status

    @staticmethod
    def get_service_config_file_path(service_name):
        """Returns the path to a supervisord service config file
        for a given service_name.
        (e.g./etc/supervisord.d/rabbitmq.cloudify.conf)
        """
        return "/etc/supervisord.d/{0}.cloudify.conf".format(service_name)

    def configure(self,
                  service_name,
                  user=CLOUDIFY_USER,
                  group=CLOUDIFY_GROUP,
                  external_configure_params=None,
                  config_path='config/supervisord',
                  src_dir=None,
                  render=True):
        """This configures supervisord for a specific service.
        It requires that two files are present for each service one containing
        the environment variables and one containing the systemd config.
        All env files will be named "cloudify-SERVICENAME".
        All supervisord config files will be named "SERVICENAME.cloudify.conf".
        """
        dst = '/etc/supervisord.d/{0}.cloudify.conf'.format(service_name)

        if src_dir is None:
            src_dir = _strip_prefix(service_name)
        src_dir = src_dir.replace('-', '_')
        srv_src = join(COMPONENTS_DIR, src_dir, config_path)
        srv_src = join(srv_src, '{0}.conf'.format(service_name))
        if exists(srv_src):
            logger.debug('Deploying supervisord service file...')
            deploy(srv_src, dst, render=render,
                   additional_render_context=external_configure_params)
            chown(user, group, dst)

    def remove(self, service_name):
        """Stop and disable the service, and then delete its data
        """
        self.stop(service_name, ignore_failure=True)
        self.disable(service_name, ignore_failure=True)
        remove_file(self.get_service_config_file_path(service_name))

    def reread(self):
        return self.supervisorctl('reread')


def _get_service_type():
    service_type = config.get('service_management')
    if not service_type:
        service_type = 'systemd'
    return service_type


def _get_backend():
    if _get_service_type() == 'supervisord':
        return Supervisord()
    else:
        return SystemD()


def _supervisord_service_name(service_name: str, is_group: bool):
    return service_name + (':*' if is_group else '')


def enable(service_name):
    logger.debug('Enabling service {0}...'.format(service_name))
    return _get_backend().enable(service_name)


def disable(service_name):
    logger.debug('Disabling service {0}...'.format(service_name))
    return _get_backend().disable(service_name)


def start(service_name, is_group=False, options=None, ignore_failure=False):
    logger.debug('Starting service {0}...'.format(service_name))
    return _get_backend().start(service_name, is_group, options=options,
                                ignore_failure=ignore_failure)


def stop(service_name, is_group=False):
    logger.debug('Stopping service {0}...'.format(service_name))
    return _get_backend().stop(service_name, is_group)


def restart(service_name, is_group=False, ignore_failure=False):
    logger.debug('Restarting service {0}...'.format(service_name))
    return _get_backend().restart(service_name, is_group, ignore_failure)


def remove(service_name):
    logger.debug('Removing service {0}...'.format(service_name))
    return _get_backend().remove(service_name)


def reload(service_name, ignore_failure=False):
    logger.debug('Reloading service {0}...'.format(service_name))
    return _get_backend().reload(service_name, ignore_failure=ignore_failure)


def reread():
    logger.debug('Reloading service files...')
    return _get_backend().reread()


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def verify_alive(service_name, is_group=False):
    if _get_backend().is_alive(service_name, is_group):
        logger.debug('{0} is running'.format(service_name))
    else:
        raise ValidationError('{0} is not running'.format(service_name))


def is_alive(service_name):
    return _get_backend().is_alive(service_name)


def is_active(service_name):
    return _get_backend().is_active(service_name)


def is_installed(service_name):
    return _get_backend().is_installed(service_name)


def configure(service_name,
              user=CLOUDIFY_USER,
              group=CLOUDIFY_GROUP,
              external_configure_params=None,
              config_path=None,
              render=True,
              src_dir=None):
    _configure = \
        partial(
            _get_backend().configure,
            service_name,
            user=user,
            group=group,
            external_configure_params=external_configure_params,
            render=render,
            src_dir=src_dir
        )
    if config_path:
        return _configure(config_path=config_path)
    else:
        return _configure()


def _strip_prefix(service_name):
    legacy_prefix = 'cloudify-'
    if service_name.startswith(legacy_prefix):
        return service_name[len(legacy_prefix):]
    return service_name
