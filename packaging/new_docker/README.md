# Manager Docker Image
## Building the docker image

Navigate to packaging/new_docker, and do:
```
docker build -t cloudify-manager --build-arg rpm_file=<rpm_filename.rpm> .
```
Additionally, build the queue docker image separately by passing `-t cloudify-manager-queue -f Dockerfile.queue`.


## Running a container
Note that the config file must include the following to use the new service management.
```
service_management: supervisord
skip_sudo: true
save_config: false
```
When mounting the config file, make sure to set up permissions so that the in-container user is able to read the mounted config file.
The in-container cfyuser user (in the manager image) is created with UID 1500, and the in-container rabbitmq user (in the queue image) is created with UID 1501.

Example config.yaml files for all the containers are inside of .circleci/new_docker

1. First, create a database, for example by doing `docker run --name postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=postgres -e POSTGRES_PASSWORD=postgres -d postgres`.
2. Then, create the queue container: `docker run --name cloudify-manager-queue -d -v $(pwd)/config_queue.yaml:/etc/cloudify/config.yaml cloudify-manager-queue`.
3. Allow some time (about 10 seconds) for the queue container to boot.
4. Set up certificates as needed, eg. copy the rabbitmq CA cert out of the queue container so that it can be mounted in the manager container.
5. Run the manager container:
```bash
docker run \
    --name cloudify-manager \
    -d \
    -v $(pwd)/config.yaml:/tmp/config.yaml \
    --cap-drop SETUID \
    --cap-drop SETGID \
    --cap-drop NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    cloudify-manager
```
