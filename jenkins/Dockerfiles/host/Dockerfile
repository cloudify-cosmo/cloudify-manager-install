FROM centos:7
ARG uid=1500
ARG gid=1500
RUN groupadd -g $gid cfyuser
RUN useradd -ms /bin/bash -g $gid --home-dir /etc/cloudify -u $uid cfyuser
RUN yum -y update && \
yum install -y nc iputils
RUN yum install -y openssh-server openssh-clients sudo
RUN mkdir -p ~/.ssh && \
chmod 755 ~/.ssh
RUN ssh-keygen -A
RUN mkdir -p /var/run/sshd && \
chmod 755 /var/run/sshd
RUN yum install -y openssl-1.0.2k libselinux-utils \
    logrotate python-setuptools python-backports \
    python-backports-ssl_match_hostname which cronie \
    systemd-sysv initscripts tcp_wrappers-libs sudo
RUN yum -y install http://repository.cloudifysource.org/cloudify/cloudify-cluster-manager/1.0.3/ga-release/cloudify-cluster-manager-1.0.3-ga.el7.x86_64.rpm
RUN yum -y install epel-release
RUN yum -y install haveged
ADD /root/pkey.pem.pub /root/.ssh/authorized_keys
ADD /root/pkey.pem /root/
ADD /root/cloudify-manager-install/jenkins/config_env_three_nodes.yaml /cfy_cluster_config
ADD /root/cloudify-manager-install/jenkins/Dev-PS_cloudify_license.yaml /root/
EXPOSE 22 80 443 5672 53333
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/sbin/init"]