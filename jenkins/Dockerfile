FROM centos:7
RUN yum -y update && \
yum install -y nc iputils
RUN yum install -y openssh-server openssh-clients
RUN mkdir -p ~/.ssh && \
chmod 755 ~/.ssh
RUN ssh-keygen -A
RUN mkdir -p /var/run/sshd && \
chmod 755 /var/run/sshd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]