FROM centos:7

ARG rpm_file
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

EXPOSE 80 443 5671 53333
COPY $config /tmp/config.yaml

RUN curl -o /tmp/cloudify-manager-install.rpm $rpm_file \
    && yum install -y /tmp/cloudify-manager-install.rpm \
    && rm /tmp/cloudify-manager-install.rpm \
    && cp /tmp/config.yaml /etc/cloudify/config.yaml \
    && cfy_manager install --only-install --verbose \
    && rm -fr /opt/cloudify/sources/*.rpm -fr \
    && rm /etc/yum.repos.d/Cloudify-Local.repo \
    && yum autoremove -y \
    && yum clean all

RUN chmod a+wx /var/run
RUN chmod 755 /etc/cloudify
RUN ssh-keygen -A
RUN mkdir -p /etc/supervisord.d

COPY sshd.conf /etc/supervisord.d/
COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]