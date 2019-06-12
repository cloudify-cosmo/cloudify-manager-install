FROM cfy_manager_image

COPY *.rpm /tmp
RUN yum install -y /tmp/*.rpm && rm -rf /tmp/*.rpm
