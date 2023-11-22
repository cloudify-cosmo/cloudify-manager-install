ARG base_image=centos:7
FROM $base_image

ARG rpm_file
ARG lightweight=""
ARG config=config.yaml
ARG arch=x86_64
ARG uid=1500
ARG gid=1500

RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser

RUN yum install -y openssl-1.0.2k libselinux-utils \
    logrotate python-setuptools python-backports \
    python-backports-ssl_match_hostname which cronie \
    initscripts tcp_wrappers-libs openssh-clients sudo \
    systemd-sysv  # systemd-sysv is required by postgres

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
    # in "lightweight" mode, the UI is not installed
    # ...really, it is uninstalled. For the 7.x branch, we can't edit the code
    # itself to not install it, but we can uninstall it afterwards.
    && if [ "$lightweight" ]; then yum erase -y cloudify-composer cloudify-stage; fi \
    && yum clean all
    && yum update -y

RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

RUN usermod -aG cfyuser rabbitmq || true
RUN chmod g+rx /etc/cloudify
RUN chmod a+wx /var/run
COPY starter.conf /etc/supervisord.d/starter.conf
RUN if [ "$arch" = "aarch64" ]; then echo 'DefaultEnvironment="LD_LIBRARY_PATH"=/usr/local/lib64:${LD_LIBRARY_PATH}' >> /etc/systemd/system.conf; fi
RUN if [ "$arch" = "aarch64" ]; then echo 'LD_LIBRARY_PATH=/usr/local/lib64:${LD_LIBRARY_PATH}' > /etc/environment; fi

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
