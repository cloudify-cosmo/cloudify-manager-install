FROM centos:7

ARG rpm_file
ARG config=config.yaml
ARG uid=1500
ARG gid=1500

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

RUN yum install -y openssl-1.0.2k libselinux-utils \
    logrotate python-setuptools python-backports \
    python-backports-ssl_match_hostname which cronie \
    systemd-sysv initscripts tcp_wrappers-libs sudo \
    openssh-clients

EXPOSE 80 443 5672 53333
COPY $config /tmp/config.yaml

# `curl && yum install && rm` is the method that results in the lowest
# overhead for the image size, even smaller than `yum install $url`.
# All of this is in a single RUN layer so that intermediate files don't
# increase the image size.
RUN curl -o /tmp/cloudify-manager-install.rpm $rpm_file \
    && yum install -y /tmp/cloudify-manager-install.rpm \
    && rm /tmp/cloudify-manager-install.rpm \
    && cp /tmp/config.yaml /etc/cloudify/config.yaml \
    && cfy_manager install --only-install --verbose \
    && rm -fr /opt/cloudify/sources/*.rpm -fr \
    && rm /etc/yum.repos.d/Cloudify-Local.repo \
    && yum autoremove -y \
    && yum clean all

COPY starter.service /usr/lib/systemd/system/cloudify-starter.service
RUN systemctl enable cloudify-starter.service

RUN usermod -aG cfyuser rabbitmq || true
RUN chmod g+rx /etc/cloudify
RUN mkdir -p /etc/supervisord.d
RUN chmod a+wx /var/run
COPY supervisord.conf /etc/supervisord.conf

STOPSIGNAL SIGRTMIN+3
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/bin/cfy_manager", "run-init"]
