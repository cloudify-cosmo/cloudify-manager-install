FROM registry.access.redhat.com/ubi8/ubi:8.0

ARG rpm_file
ARG config=config.yaml
ARG arch=x86_64
ARG uid=1500
ARG gid=1500

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

RUN sed -i 's/enabled=1/enabled=0/g' /etc/yum/pluginconf.d/subscription-manager.conf
RUN yum makecache --refresh

RUN yum update -y && yum -y install epel-release && \
    yum clean all -y

RUN yum install -y openssl-1.1.1k libselinux-utils \
    logrotate python3-setuptools \
    which cronie initscripts \
    openssh-clients sudo systemd-sysv \
    dbus-glib ncurses libpq compat-openssl10 iproute \
    && yum clean all -y
    

EXPOSE 80 443 5671 53333
COPY $config /tmp/config.yaml

# `curl && yum install && rm` is the method that results in the lowest
# overhead for the image size, even smaller than `yum install $url`.
# All of this is in a single RUN layer so that intermediate files don't
# increase the image size.
# In Aarch64 we don't do `yum autoremove` as it tries to remove kernel-core
# and fails for some reason
RUN curl -o /tmp/cloudify-manager-install.rpm $rpm_file \
    && yum install -y /tmp/cloudify-manager-install.rpm \
    && rm /tmp/cloudify-manager-install.rpm \
    && cp /tmp/config.yaml /etc/cloudify/config.yaml \
    && cfy_manager install --only-install --verbose \
    && sed -i 's/ssl_enabled: true/ssl_enabled: false/' /opt/cloudify/cfy_manager/lib/python3.11/site-packages/config.yaml \
    && rm -fr /opt/cloudify/sources/*.rpm -fr \
    && rm /etc/yum.repos.d/Cloudify-Local.repo \
    && if [ "$arch" != "aarch64" ]; then yum autoremove -y; fi \
    && yum clean all

RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

RUN usermod -aG cfyuser rabbitmq || true
RUN chmod g+rx /etc/cloudify
RUN chmod a+wx /var/run
COPY starter.conf /etc/supervisord.d/starter.conf

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
