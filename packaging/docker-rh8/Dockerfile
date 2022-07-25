FROM registry.access.redhat.com/ubi8/ubi:8.0

ARG rpm_file
ARG config=config.yaml
ARG arch=x86_64
ARG uid=1500
ARG gid=1500

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

RUN yum makecache --refresh
RUN yum install -y https://repo.almalinux.org/almalinux/8/BaseOS/$arch/os/Packages/libnsl-2.28-189.5.el8_6.$arch.rpm \
    https://repo.almalinux.org/almalinux/8/BaseOS/$arch/os/Packages/glibc-2.28-189.5.el8_6.$arch.rpm \
    https://repo.almalinux.org/almalinux/8/BaseOS/$arch/os/Packages/glibc-common-2.28-189.5.el8_6.$arch.rpm \
    https://repo.almalinux.org/almalinux/8/BaseOS/$arch/os/Packages/glibc-langpack-en-2.28-189.5.el8_6.$arch.rpm
RUN yum install -y openssl-1.1.1k libselinux-utils \
    logrotate python3-setuptools which cronie \
    initscripts openssh-clients sudo \
    dbus-glib ncurses libpq compat-openssl10 iproute

EXPOSE 80 443 5672 53333
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
    && sed -i 's/ssl_enabled: true/ssl_enabled: false/' /opt/cloudify/cfy_manager/lib/python3.6/site-packages/config.yaml \
    && rm -fr /opt/cloudify/sources/*.rpm -fr \
    && rm /etc/yum.repos.d/Cloudify-Local.repo \
    && if [ "$arch" != "aarch64" ]; then yum autoremove -y; fi \
    && yum clean all

COPY starter.service /usr/lib/systemd/system/cloudify-starter.service
RUN systemctl enable cloudify-starter.service

RUN usermod -aG cfyuser rabbitmq || true
RUN chmod g+rx /etc/cloudify
RUN chmod a+wx /var/run
COPY starter.conf /etc/supervisord.d/starter.conf

STOPSIGNAL SIGRTMIN+3
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/bin/cfy_manager", "run-init"]