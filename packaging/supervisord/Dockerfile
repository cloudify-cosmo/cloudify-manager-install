FROM centos:7

ARG rpm_file=cloudify-manager-install.rpm
ARG config=config.yaml
ARG uid=1500
ARG gid=1500
ARG reporter_uid=1501
ARG reporter_gid=1501

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

# This should save some time for the installations of all these programs
RUN yum install -y openssl-1.0.2k libselinux-utils \
    logrotate python-setuptools python-backports \
    python-backports-ssl_match_hostname which cronie \
    systemd-sysv initscripts tcp_wrappers-libs sudo openssh-server
RUN easy_install supervisor

EXPOSE 80 443 5671 53333

COPY $rpm_file /tmp/cloudify-manager-install.rpm
COPY $config /etc/cloudify/config.yaml

RUN yum install -y /tmp/cloudify-manager-install.rpm && rm /tmp/cloudify-manager-install.rpm
RUN cfy_manager install --only-install --verbose
RUN chmod a+wx /var/run
RUN chmod 755 /etc/cloudify
RUN chown cfyuser. /run/cloudify-restservice && chmod 755 /run/cloudify-restservice
RUN mkdir /etc/supervisord.d

RUN groupadd supervisor
RUN usermod -a -G supervisor cfyuser
RUN usermod -a -G supervisor cfyreporter

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]