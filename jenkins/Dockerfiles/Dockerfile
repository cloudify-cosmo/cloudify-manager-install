FROM centos:7
RUN yum -y update && \
yum install -y nc iputils
RUN yum install -y openssh-server openssh-clients sudo
RUN mkdir -p ~/.ssh && \
chmod 755 ~/.ssh
RUN ssh-keygen -A
RUN mkdir -p /var/run/sshd && \
chmod 755 /var/run/sshd
COPY ~/pkey.pem.pub /root/.ssh/authorized_keys
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in ; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done);
RUN rm -rf /lib/systemd/system/multi-user.target.wants/ \
    && rm -rf /etc/systemd/system/.wants/ \
    && rm -rf /lib/systemd/system/local-fs.target.wants/ \
    && rm -f /lib/systemd/system/sockets.target.wants/udev \
    && rm -f /lib/systemd/system/sockets.target.wants/initctl \
    && rm -rf /lib/systemd/system/basic.target.wants/ \
    && rm -f /lib/systemd/system/anaconda.target.wants/*
VOLUME [ “/sys/fs/cgroup” ]
EXPOSE 22
CMD ["/usr/sbin/init"]
#EXPOSE 22
#CMD ["/usr/sbin/sshd", "-D"]