DEPENDENCIES_ERROR_MESSAGES = {
    'sudo': 'necessary to run commands with root privileges',
    'openssl-1.0.2k': 'necessary for creating certificates',
    'openssl-1.1.1k': 'necessary for creating certificates',
    'logrotate': 'used in Cloudify logs',
    'initscripts': 'required by the RabbitMQ server',
    'sed': 'required by the CLI',
    'tar': 'required to untar packages',
    'yum': 'used to install Cloudify\'s required packages',
    'python-setuptools': 'required by python',
    'python-backports': 'required by python',
    'python-backports-ssl_match_hostname': 'required by python',
    'python3-setuptools': 'required by python',
}

COMPONENTS_DEPENDENCIES = {
    'default': ['sudo', 'logrotate', 'yum', 'python-setuptools',
                'python-backports', 'python-backports-ssl_match_hostname'],
    'Cli': ['sed'],
    'Composer': [],
    'AmqpPostgres': [],
    'Manager': [],
    'MgmtWorker': [],
    'Nginx': ['openssl-1.0.2k'],
    'PostgresqlServer': [],
    'PostgresqlClient': [],
    'Python': [],
    'RabbitMQ': ['initscripts'],
    'RestService': [],
    'Sanity': [],
    'Stage': [],
    'UsageCollector': [],
    'Patch': [],
    'Prometheus': [],
    'Haveged': [],
    'ExecutionScheduler': [],
    'Rsyslog': [],
}

COMPONENTS_DEPENDENCIES_RH8 = COMPONENTS_DEPENDENCIES.copy()
COMPONENTS_DEPENDENCIES_RH8['default'] = \
    ['sudo', 'logrotate', 'yum', 'python3-setuptools']
COMPONENTS_DEPENDENCIES_RH8['Nginx'] = ['openssl-1.1.1k']
