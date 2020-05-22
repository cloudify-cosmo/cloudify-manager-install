FROM centos:7

ARG rpm_file=cloudify-manager-install.rpm
ARG config=config.yaml
ARG uid=1500
ARG gid=1500
ARG reporter_uid=1501
ARG reporter_gid=1501

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser
# reporter's primary group is still cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $reporter_uid cfyreporter
RUN groupadd -g $reporter_gid cfyreporter

RUN yum install -y openssl-1.0.2k libselinux-utils \
    logrotate python-setuptools python-backports \
    python-backports-ssl_match_hostname which cronie \
    systemd-sysv initscripts tcp_wrappers-libs sudo \
    openssh-server

EXPOSE 80 443 5672 53333

COPY $rpm_file /tmp/cloudify-manager-install.rpm
RUN yum install -y /tmp/cloudify-manager-install.rpm && rm /tmp/cloudify-manager-install.rpm
COPY $config /etc/cloudify/config.yaml
RUN cfy_manager install --only-install --verbose

COPY starter.sh /opt/cloudify/starter.sh
COPY starter.service /usr/lib/systemd/system/cloudify-starter.service
RUN systemctl enable cloudify-starter.service

RUN usermod -aG cfyuser rabbitmq
RUN chmod g+rx /etc/cloudify

STOPSIGNAL SIGRTMIN+3
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/bin/bash", "-c", "exec /sbin/init --log-target=journal 3>&1"]
