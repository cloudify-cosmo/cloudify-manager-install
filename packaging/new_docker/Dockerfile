FROM registry.access.redhat.com/ubi7/ubi

ARG rpm_file=cloudify-manager-install.rpm
ARG config=config.yaml
ARG uid=1500
ARG gid=1500

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

# This should save some time for the installations of all these programs
RUN yum install -y openssl-1.0.2k libselinux-utils \
    logrotate python-setuptools python-backports \
    python-backports-ssl_match_hostname which cronie \
    systemd-sysv initscripts tcp_wrappers-libs sudo
RUN easy_install supervisor

EXPOSE 80 443 53333

COPY $rpm_file /tmp/cloudify-manager-install.rpm
RUN yum install -y /tmp/cloudify-manager-install.rpm && rm /tmp/cloudify-manager-install.rpm
COPY $config /etc/cloudify/config.yaml
COPY starter.sh /opt/cloudify-starter.sh
RUN chmod +x /opt/cloudify-starter.sh
RUN cfy_manager install --only-install --verbose
RUN mkdir /etc/supervisord.d && chown cfyuser: /etc/supervisord.d
RUN chown cfyuser: -R /etc/nginx \
    /var/log/nginx \
    /opt/cloudify-composer/backend \
    /opt/status-reporter \
    /opt/cloudify-stage/dist \
    /opt/cloudify-stage/conf \
    /etc/rabbitmq \
    /var/log/cloudify \
    /var/lib/rabbitmq \
    /var/log/rabbitmq || true
RUN chown -f cfyuser: /opt/cloudify-stage \
    /opt/cloudify-composer \
    /var/cache/nginx \
    /run/cloudify-restservice \
    /run/rabbitmq || true

RUN chmod a+wx /var/run
RUN rm /etc/cloudify/config.yaml

USER cfyuser
COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
