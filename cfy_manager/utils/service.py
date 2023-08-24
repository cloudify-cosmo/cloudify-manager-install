import http.client
import socket
import subprocess
import xmlrpc.client
from functools import partial
from os.path import exists, join

from retrying import retry

from .common import (
    chown,
    run,
)
from .files import deploy, remove as remove_file
from ..constants import (
    COMPONENTS_DIR,
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ..exceptions import ValidationError
from ..logger import get_logger

logger = get_logger('Service')

ACTIVE_STATES = ['running', 'active', 'activating']


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.host)


class UnixSocketTransport(xmlrpc.client.Transport, object):
    def __init__(self, path):
        super(UnixSocketTransport, self).__init__()
        self._path = path

    def make_connection(self, host):
        return UnixSocketHTTPConnection(self._path)


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


def _supervisord_service_name(service_name: str, is_group: bool):
    return service_name + (':*' if is_group else '')


def enable(service_name):
    logger.debug('Enabling service {0}...'.format(service_name))
    return Supervisord().enable(service_name)


def disable(service_name):
    logger.debug('Disabling service {0}...'.format(service_name))
    return Supervisord().disable(service_name)


def start(service_name, is_group=False, options=None, ignore_failure=False):
    logger.debug('Starting service {0}...'.format(service_name))
    return Supervisord().start(service_name, is_group, options=options,
                               ignore_failure=ignore_failure)


def stop(service_name, is_group=False):
    logger.debug('Stopping service {0}...'.format(service_name))
    return Supervisord().stop(service_name, is_group)


def restart(service_name, is_group=False, ignore_failure=False):
    logger.debug('Restarting service {0}...'.format(service_name))
    return Supervisord().restart(service_name, is_group, ignore_failure)


def remove(service_name):
    logger.debug('Removing service {0}...'.format(service_name))
    return Supervisord().remove(service_name)


def reload(service_name, ignore_failure=False):
    logger.debug('Reloading service {0}...'.format(service_name))
    return Supervisord().reload(service_name, ignore_failure=ignore_failure)


def reread():
    logger.debug('Reloading service files...')
    return Supervisord().reread()


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def verify_alive(service_name, is_group=False):
    if Supervisord().is_alive(service_name, is_group):
        logger.debug('{0} is running'.format(service_name))
    else:
        raise ValidationError('{0} is not running'.format(service_name))


def is_alive(service_name):
    return Supervisord().is_alive(service_name)


def is_active(service_name):
    return Supervisord().is_active(service_name)


def is_installed(service_name):
    return Supervisord().is_installed(service_name)


def configure(service_name,
              user=CLOUDIFY_USER,
              group=CLOUDIFY_GROUP,
              external_configure_params=None,
              config_path=None,
              render=True,
              src_dir=None):
    _configure = \
        partial(
            Supervisord().configure,
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


def using_systemd_service(service_name):
    """Check if a service is already running under systemd

    Some services (eg. haveged or rsyslog) can already be running on this
    machine. In that case, we're not going to bring our own.
    """
    try:
        # first, check if we have systemd at all
        is_running = subprocess.run(
            ['/bin/systemctl', 'is-system-running'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout.strip()
        if not is_running:
            # systemctl always gives SOME stdout ("active", "degraded") only if
            # systemd exists
            return False
    except FileNotFoundError:
        # no systemctl at all, so there for sure won't be systemd services
        return False

    if subprocess.run(
        ['/bin/systemctl', 'is-active', service_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.decode('utf-8').strip().lower() == 'active':
        logger.notice('Using system %s', service_name)
        return True

    return False
