FROM centos:7

ARG rpm_file=cloudify-manager-install.rpm
ARG uid=1500
ARG gid=1500

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

# This should save some time for the installations of all these programs
RUN yum install -y deltarpm
RUN yum install -y epel-release
RUN yum install -y initscripts sudo openssh-server systemd-sysv openssl-1.0.2k \
    libselinux-utils logrotate python-setuptools \
    python-backports python-backports-ssl_match_hostname which cronie
RUN yum install -y supervisor

EXPOSE 80 443 53333

# Should help to stop the container gracfully

COPY $rpm_file /tmp/cloudify-manager-install.rpm
RUN yum install -y /tmp/cloudify-manager-install.rpm && rm /tmp/cloudify-manager-install.rpm
COPY config.yaml /etc/cloudify/config.yaml
COPY starter.sh /opt/cloudify-starter.sh
RUN chmod +x /opt/cloudify-starter.sh
RUN cfy_manager install --only-install --verbose
RUN mkdir -p /var/log/supervisor
RUN mkdir /run/cloudify-restservice
RUN chown cfyuser: -R /var/log/cloudify \
    /etc/nginx \
    /etc/cloudify \
    /var/log/nginx \
    /opt/cloudify-stage \
    /opt/cloudify-composer \
    /opt/syncthing \
    /opt/manager \
    /opt/mgmtworker \
    /opt/status-reporter
RUN chown cfyuser: /etc/supervisord.d \
    /opt/manager \
    /opt/cloudify \
    /var/cache/nginx \
    /var/log/supervisor \
    /run/cloudify-restservice
RUN chmod a+wx /var/run
RUN rm /etc/cloudify/config.yaml

USER cfyuser
COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
