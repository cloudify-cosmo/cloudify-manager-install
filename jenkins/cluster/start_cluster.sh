#!/usr/bin/env bash
set -euxo pipefail

IMAGE=${1:-cloudify-manager-aio}
NAME_PREFIX=${2:-cfy}

echo "###### Prepare name envvars ######"
export NODE1_NAME="${NAME_PREFIX}_node1"
export NODE2_NAME="${NAME_PREFIX}_node2"
export NODE3_NAME="${NAME_PREFIX}_node3"
export MANAGER1_IP="172.22.0.3"
export MANAGER2_IP="172.22.0.4"
export MANAGER3_IP="172.22.0.5"
export DB1_IP="172.22.0.3"
export DB2_IP="172.22.0.4"
export DB3_IP="172.22.0.5"
export QUEUE1_IP="172.22.0.3"
export QUEUE2_IP="172.22.0.4"
export QUEUE3_IP="172.22.0.5"
echo "###### Create a docker network ######"
docker network create --subnet=172.22.0.0/24 net1
echo "###### generate certs ######"
chmod +x create_certs.sh
source ./create_certs.sh
set -eux
# Prepare Queue1 on Node1
sed -e "s/CONTAINER_IP/${QUEUE1_IP}/g" \
    -e "s/QUEUE2_IP/${QUEUE2_IP}/" \
    -e "s/QUEUE3_IP/${QUEUE3_IP}/" \
    queue1_config.yaml > queue_1_config.yaml
cat queue_1_config.yaml
docker run -d \
  --name ${NODE1_NAME} \
  --network net1 --ip ${QUEUE1_IP} \
  -v $(pwd)/queue_1_config.yaml:/etc/cloudify/config.yaml \
  -v $(pwd)/queue1_key.pem:/etc/cloudify/queue_key.pem \
  -v $(pwd)/queue1_cert.pem:/etc/cloudify/queue_cert.pem \
  -v $(pwd)/ca.crt:/etc/cloudify/ca.pem \
  ${IMAGE}
docker exec ${NODE1_NAME} cfy_manager wait-for-starter -c /etc/cloudify/config.yaml
docker cp queue_1_config.yaml ${NODE1_NAME}:/etc/cloudify/queue_config.yaml
# Prepare Queue2 on Node 2
sed -e "s/CONTAINER_IP/${QUEUE2_IP}/g" \
    -e "s/QUEUE1_IP/${QUEUE1_IP}/" \
    -e "s/QUEUE3_IP/${QUEUE3_IP}/" \
    queue2_config.yaml > queue_2_config.yaml
cat queue_2_config.yaml
docker run -d \
  --name ${NODE2_NAME} \
  --network net1 --ip ${QUEUE2_IP} \
  -v $(pwd)/queue_2_config.yaml:/etc/cloudify/config.yaml \
  -v $(pwd)/queue2_key.pem:/etc/cloudify/queue_key.pem \
  -v $(pwd)/queue2_cert.pem:/etc/cloudify/queue_cert.pem \
  -v $(pwd)/ca.crt:/etc/cloudify/ca.pem \
  ${IMAGE}
docker exec ${NODE2_NAME} cfy_manager wait-for-starter -c /etc/cloudify/config.yaml
docker cp queue_2_config.yaml ${NODE2_NAME}:/etc/cloudify/queue_config.yaml
# Prepare Queue3 on Node 3
sed -e "s/CONTAINER_IP/${QUEUE3_IP}/g" \
    -e "s/QUEUE1_IP/${QUEUE1_IP}/" \
    -e "s/QUEUE2_IP/${QUEUE2_IP}/" \
    queue3_config.yaml > queue_3_config.yaml
cat queue_3_config.yaml
docker run -d \
   --name ${NODE3_NAME} \
   --network net1 --ip ${QUEUE3_IP} \
   -v $(pwd)/queue_3_config.yaml:/etc/cloudify/config.yaml \
   -v $(pwd)/queue3_key.pem:/etc/cloudify/queue_key.pem \
   -v $(pwd)/queue3_cert.pem:/etc/cloudify/queue_cert.pem \
   -v $(pwd)/ca.crt:/etc/cloudify/ca.pem \
  ${IMAGE}
docker exec ${NODE3_NAME} cfy_manager wait-for-starter -c /etc/cloudify/config.yaml
docker cp queue_3_config.yaml ${NODE3_NAME}:/etc/cloudify/queue_config.yaml
# Prepare DB1 on Node1
sed -e "s/CONTAINER_IP/${DB1_IP}/g" \
    -e "s/DB1_IP/${DB1_IP}/g" \
    -e "s/DB2_IP/${DB2_IP}/g" \
    -e "s/DB3_IP/${DB3_IP}/g" \
    db_config.yaml > db1_config.yaml
cat db1_config.yaml
sudo docker cp db1_config.yaml ${NODE1_NAME}:/etc/cloudify/db_config.yaml
sudo docker cp db1_key.pem ${NODE1_NAME}:/etc/cloudify/db_key.pem
sudo docker cp db1_cert.pem ${NODE1_NAME}:/etc/cloudify/db_cert.pem
sudo docker exec ${NODE1_NAME} cfy_manager configure -c  /etc/cloudify/db_config.yaml
# Prepare DB2 on Node2
sed -e "s/CONTAINER_IP/${DB2_IP}/g" \
    -e "s/DB1_IP/${DB1_IP}/g" \
    -e "s/DB2_IP/${DB2_IP}/g" \
    -e "s/DB3_IP/${DB3_IP}/g" \
    db_config.yaml > db2_config.yaml
cat db2_config.yaml
sudo docker cp db2_config.yaml ${NODE2_NAME}:/etc/cloudify/db_config.yaml
sudo docker cp db2_key.pem ${NODE2_NAME}:/etc/cloudify/db_key.pem
sudo docker cp db2_cert.pem ${NODE2_NAME}:/etc/cloudify/db_cert.pem
sudo docker exec ${NODE2_NAME} cfy_manager configure -c /etc/cloudify/db_config.yaml -v
# Prepare DB3 on Node3
sed -e "s/CONTAINER_IP/${DB3_IP}/g" \
    -e "s/DB1_IP/${DB1_IP}/g" \
    -e "s/DB2_IP/${DB2_IP}/g" \
    -e "s/DB3_IP/${DB3_IP}/g" \
    db_config.yaml > db3_config.yaml
cat db3_config.yaml
sudo docker cp db3_config.yaml ${NODE3_NAME}:/etc/cloudify/db_config.yaml
sudo docker cp db3_key.pem ${NODE3_NAME}:/etc/cloudify/db_key.pem
sudo docker cp db3_cert.pem ${NODE3_NAME}:/etc/cloudify/db_cert.pem
sudo docker exec ${NODE3_NAME} cfy_manager configure -c /etc/cloudify/db_config.yaml -v
# Prepare Manager 1 on Node1
sed -e "s/CONTAINER_IP/${MANAGER1_IP}/g" \
    -e "s/QUEUE1_IP/${QUEUE1_IP}/g" \
    -e "s/QUEUE2_IP/${QUEUE2_IP}/g" \
    -e "s/QUEUE3_IP/${QUEUE3_IP}/g" \
    -e "s/DB1_IP/${DB1_IP}/g" \
    -e "s/DB2_IP/${DB2_IP}/g" \
    -e "s/DB3_IP/${DB3_IP}/g" \
    manager1_config.yaml > manager_1_config.yaml
cat manager_1_config.yaml
  # Generate ca encrypted key
openssl rsa -aes256 -passout pass:secret_ca_password -in ca.key -out ca.encrypted.key
sudo docker cp manager_1_config.yaml ${NODE1_NAME}:/etc/cloudify/manager_config.yaml
sudo docker cp manager_1_key.pem ${NODE1_NAME}:/etc/cloudify/manager_key.pem
sudo docker cp manager_1_cert.pem ${NODE1_NAME}:/etc/cloudify/manager_cert.pem
sudo docker cp db_client_1_cert.pem ${NODE1_NAME}:/etc/cloudify/manager_postgres_client_cert.pem
sudo docker cp db_client_1_key.pem ${NODE1_NAME}:/etc/cloudify/manager_postgres_client_key.pem
sudo docker cp external_key_1.pem ${NODE1_NAME}:/etc/cloudify/manager_external_key.pem
sudo docker cp external_cert_1.pem ${NODE1_NAME}:/etc/cloudify/manager_external_cert.pem
sudo docker cp ca.encrypted.key ${NODE1_NAME}:/etc/cloudify/ca_key.pem
sudo docker exec ${NODE1_NAME} cfy_manager configure -c /etc/cloudify/manager_config.yaml -v
# Prepare Manager 2 on Node2
sed -e "s/CONTAINER_IP/${MANAGER2_IP}/g" \
    -e "s/QUEUE1_IP/${QUEUE1_IP}/g" \
    -e "s/QUEUE2_IP/${QUEUE2_IP}/g" \
    -e "s/QUEUE3_IP/${QUEUE3_IP}/g" \
    -e "s/DB1_IP/${DB1_IP}/g" \
    -e "s/DB2_IP/${DB2_IP}/g" \
    -e "s/DB3_IP/${DB3_IP}/g" \
    manager2_config.yaml > manager_2_config.yaml
cat manager_2_config.yaml
sudo docker cp manager_2_config.yaml ${NODE2_NAME}:/etc/cloudify/manager_config.yaml
sudo docker cp manager_2_key.pem ${NODE2_NAME}:/etc/cloudify/manager_key.pem
sudo docker cp manager_2_cert.pem ${NODE2_NAME}:/etc/cloudify/manager_cert.pem
sudo docker cp db_client_2_cert.pem ${NODE2_NAME}:/etc/cloudify/manager_postgres_client_cert.pem
sudo docker cp db_client_2_key.pem ${NODE2_NAME}:/etc/cloudify/manager_postgres_client_key.pem
sudo docker cp external_key_2.pem ${NODE2_NAME}:/etc/cloudify/manager_external_key.pem
sudo docker cp external_cert_2.pem ${NODE2_NAME}:/etc/cloudify/manager_external_cert.pem
sudo docker cp prometheus_key_2.pem ${NODE2_NAME}:/etc/cloudify/manager_prometheus_key.pem
sudo docker cp prometheus_cert_2.pem ${NODE2_NAME}:/etc/cloudify/manager_prometheus_cert.pem
sudo docker cp ca.encrypted.key ${NODE2_NAME}:/etc/cloudify/ca_key.pem
sudo docker exec ${NODE2_NAME} cfy_manager configure -c /etc/cloudify/manager_config.yaml -v
# Prepare Manager 3 on Node3
sed -e "s/CONTAINER_IP/${MANAGER3_IP}/g" \
    -e "s/QUEUE1_IP/${QUEUE1_IP}/g" \
    -e "s/QUEUE2_IP/${QUEUE2_IP}/g" \
    -e "s/QUEUE3_IP/${QUEUE3_IP}/g" \
    -e "s/DB1_IP/${DB1_IP}/g" \
    -e "s/DB2_IP/${DB2_IP}/g" \
    -e "s/DB3_IP/${DB3_IP}/g" \
    manager3_config.yaml > manager_3_config.yaml
cat manager_3_config.yaml
sudo docker cp manager_3_config.yaml ${NODE3_NAME}:/etc/cloudify/manager_config.yaml
sudo docker cp manager_3_key.pem ${NODE3_NAME}:/etc/cloudify/manager_key.pem
sudo docker cp manager_3_cert.pem ${NODE3_NAME}:/etc/cloudify/manager_cert.pem
sudo docker cp db_client_3_cert.pem ${NODE3_NAME}:/etc/cloudify/manager_postgres_client_cert.pem
sudo docker cp db_client_3_key.pem ${NODE3_NAME}:/etc/cloudify/manager_postgres_client_key.pem
sudo docker cp external_key_3.pem ${NODE3_NAME}:/etc/cloudify/manager_external_key.pem
sudo docker cp external_cert_3.pem ${NODE3_NAME}:/etc/cloudify/manager_external_cert.pem
sudo docker cp prometheus_key_3.pem ${NODE3_NAME}:/etc/cloudify/manager_prometheus_key.pem
sudo docker cp prometheus_cert_3.pem ${NODE3_NAME}:/etc/cloudify/manager_prometheus_cert.pem
sudo docker cp ca.encrypted.key ${NODE3_NAME}:/etc/cloudify/ca_key.pem
sudo docker exec ${NODE3_NAME} cfy_manager configure -c /etc/cloudify/manager_config.yaml -v