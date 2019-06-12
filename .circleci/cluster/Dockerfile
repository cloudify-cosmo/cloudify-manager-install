# for the cluster test, prepare an image with the manager rpm preinstalled.
# That way, we only need to take the time to install it once, even though
# we start 4 containers

FROM cfy_manager_image

COPY *.rpm /tmp
RUN yum install -y /tmp/*.rpm && rm -rf /tmp/*.rpm
