#!/usr/bin/env bash
set -euxo pipefail

IMAGE=${1:-cloudify-manager-aio}
NAME_PREFIX=${2:-cfy}
echo "###### Prepare name envvars ######"
NODE1_NAME="${NAME_PREFIX}_node1"
NODE2_NAME="${NAME_PREFIX}_node2"
NODE3_NAME="${NAME_PREFIX}_node3"
MANAGER1_IP="172.22.0.3"
MANAGER2_IP="172.22.0.4"
MANAGER3_IP="172.22.0.5"
DB1_IP="172.22.0.3"
DB2_IP="172.22.0.4"
DB3_IP="172.22.0.5"
QUEUE1_IP="172.22.0.3"
QUEUE2_IP="172.22.0.4"
QUEUE3_IP="172.22.0.5"
TMPDIR=$(mktemp -d)

function create_network(){
  echo "###### Create a docker network ######"
  docker network create --subnet=172.22.0.0/24 net1
}

function create_certs(){
  echo "###### generate certs ######"
  source ./create_certs.sh
  pushd ${TMPDIR}
    generate_certs
  popd
}

function run_queue1(){
  # Prepare Queue1 on Node1
  sed -e "s/CONTAINER_IP/${QUEUE1_IP}/g" \
      -e "s/QUEUE2_IP/${QUEUE2_IP}/" \
      -e "s/QUEUE3_IP/${QUEUE3_IP}/" \
      queue1_config.yaml > ${TMPDIR}/rendered_queue1_config.yaml
  cat ${TMPDIR}/rendered_queue1_config.yaml
  docker run -d \
    --name ${NODE1_NAME} \
    --network net1 --ip ${QUEUE1_IP} \
    -v ${TMPDIR}/rendered_queue1_config.yaml:/etc/cloudify/config.yaml \
    -v ${TMPDIR}/queue1_key.pem:/etc/cloudify/queue_key.pem \
    -v ${TMPDIR}/queue1_cert.pem:/etc/cloudify/queue_cert.pem \
    -v ${TMPDIR}/ca.crt:/etc/cloudify/ca.pem \
    ${IMAGE}
  docker exec ${NODE1_NAME} cfy_manager wait-for-starter -c /etc/cloudify/config.yaml
  docker cp ${TMPDIR}/rendered_queue1_config.yaml ${NODE1_NAME}:/etc/cloudify/queue_config.yaml
}

function run_queue2(){
  # Prepare Queue2 on Node 2
  sed -e "s/CONTAINER_IP/${QUEUE2_IP}/g" \
      -e "s/QUEUE1_IP/${QUEUE1_IP}/" \
      -e "s/QUEUE3_IP/${QUEUE3_IP}/" \
      queue2_config.yaml > ${TMPDIR}/rendered_queue2_config.yaml
  cat ${TMPDIR}/rendered_queue2_config.yaml
  docker run -d \
    --name ${NODE2_NAME} \
    --network net1 --ip ${QUEUE2_IP} \
    -v ${TMPDIR}/rendered_queue2_config.yaml:/etc/cloudify/config.yaml \
    -v ${TMPDIR}/queue2_key.pem:/etc/cloudify/queue_key.pem \
    -v ${TMPDIR}/queue2_cert.pem:/etc/cloudify/queue_cert.pem \
    -v ${TMPDIR}/ca.crt:/etc/cloudify/ca.pem \
    ${IMAGE}
  docker exec ${NODE2_NAME} cfy_manager wait-for-starter -c /etc/cloudify/config.yaml
  docker cp ${TMPDIR}/rendered_queue2_config.yaml ${NODE2_NAME}:/etc/cloudify/queue_config.yaml
}

function run_queue3(){
  # Prepare Queue3 on Node 3
  sed -e "s/CONTAINER_IP/${QUEUE3_IP}/g" \
      -e "s/QUEUE1_IP/${QUEUE1_IP}/" \
      -e "s/QUEUE2_IP/${QUEUE2_IP}/" \
      queue3_config.yaml > ${TMPDIR}/rendered_queue3_config.yaml
  cat ${TMPDIR}/rendered_queue3_config.yaml
  docker run -d \
     --name ${NODE3_NAME} \
     --network net1 --ip ${QUEUE3_IP} \
     -v ${TMPDIR}/rendered_queue3_config.yaml:/etc/cloudify/config.yaml \
     -v ${TMPDIR}/queue3_key.pem:/etc/cloudify/queue_key.pem \
     -v ${TMPDIR}/queue3_cert.pem:/etc/cloudify/queue_cert.pem \
     -v ${TMPDIR}/ca.crt:/etc/cloudify/ca.pem \
    ${IMAGE}
  docker exec ${NODE3_NAME} cfy_manager wait-for-starter -c /etc/cloudify/config.yaml
  docker cp ${TMPDIR}/rendered_queue3_config.yaml ${NODE3_NAME}:/etc/cloudify/queue_config.yaml
}

function run_db1(){
  # Prepare DB1 on Node1
  sed -e "s/CONTAINER_IP/${DB1_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      db_config.yaml > ${TMPDIR}/rendered_db1_config.yaml
  cat ${TMPDIR}/rendered_db1_config.yaml
  sudo docker cp ${TMPDIR}/rendered_db1_config.yaml ${NODE1_NAME}:/etc/cloudify/db_config.yaml
  sudo docker cp ${TMPDIR}/db1_key.pem ${NODE1_NAME}:/etc/cloudify/db_key.pem
  sudo docker cp ${TMPDIR}/db1_cert.pem ${NODE1_NAME}:/etc/cloudify/db_cert.pem
  sudo docker exec ${NODE1_NAME} cfy_manager configure -c  /etc/cloudify/db_config.yaml
}

function run_db2(){
  # Prepare DB2 on Node2
  sed -e "s/CONTAINER_IP/${DB2_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      db_config.yaml > ${TMPDIR}/rendered_db2_config.yaml
  cat ${TMPDIR}/rendered_db2_config.yaml
  sudo docker cp ${TMPDIR}/rendered_db2_config.yaml ${NODE2_NAME}:/etc/cloudify/db_config.yaml
  sudo docker cp ${TMPDIR}/db2_key.pem ${NODE2_NAME}:/etc/cloudify/db_key.pem
  sudo docker cp ${TMPDIR}/db2_cert.pem ${NODE2_NAME}:/etc/cloudify/db_cert.pem
  sudo docker exec ${NODE2_NAME} cfy_manager configure -c /etc/cloudify/db_config.yaml -v
}

function run_db3(){
  # Prepare DB3 on Node3
  sed -e "s/CONTAINER_IP/${DB3_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      db_config.yaml > ${TMPDIR}/rendered_db3_config.yaml
  cat ${TMPDIR}/rendered_db3_config.yaml
  sudo docker cp ${TMPDIR}/rendered_db3_config.yaml ${NODE3_NAME}:/etc/cloudify/db_config.yaml
  sudo docker cp ${TMPDIR}/db3_key.pem ${NODE3_NAME}:/etc/cloudify/db_key.pem
  sudo docker cp ${TMPDIR}/db3_cert.pem ${NODE3_NAME}:/etc/cloudify/db_cert.pem
  sudo docker exec ${NODE3_NAME} cfy_manager configure -c /etc/cloudify/db_config.yaml -v
}

function run_manager1(){
  # Prepare Manager 1 on Node1
  sed -e "s/CONTAINER_IP/${MANAGER1_IP}/g" \
      -e "s/QUEUE1_IP/${QUEUE1_IP}/g" \
      -e "s/QUEUE2_IP/${QUEUE2_IP}/g" \
      -e "s/QUEUE3_IP/${QUEUE3_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      manager1_config.yaml > ${TMPDIR}/rendered_manager1_config.yaml
  cat ${TMPDIR}/rendered_manager1_config.yaml
    # Generate ca encrypted key
  openssl rsa -aes256 -passout pass:secret_ca_password -in ${TMPDIR}/ca.key -out ${TMPDIR}/ca.encrypted.key
  sudo docker cp ${TMPDIR}/rendered_manager1_config.yaml ${NODE1_NAME}:/etc/cloudify/manager_config.yaml
  sudo docker cp ${TMPDIR}/manager_1_key.pem ${NODE1_NAME}:/etc/cloudify/manager_key.pem
  sudo docker cp ${TMPDIR}/manager_1_cert.pem ${NODE1_NAME}:/etc/cloudify/manager_cert.pem
  sudo docker cp ${TMPDIR}/cloudify.crt ${NODE1_NAME}:/etc/cloudify/manager_postgres_client_cert.pem
  sudo docker cp ${TMPDIR}/cloudify.key ${NODE1_NAME}:/etc/cloudify/manager_postgres_client_key.pem
  sudo docker cp ${TMPDIR}/postgres.crt ${NODE1_NAME}:/etc/cloudify/manager_postgres_su_client_cert.pem
  sudo docker cp ${TMPDIR}/postgres.key ${NODE1_NAME}:/etc/cloudify/manager_postgres_su_client_key.pem
  sudo docker cp ${TMPDIR}/external_key_1.pem ${NODE1_NAME}:/etc/cloudify/manager_external_key.pem
  sudo docker cp ${TMPDIR}/external_cert_1.pem ${NODE1_NAME}:/etc/cloudify/manager_external_cert.pem
  sudo docker cp ${TMPDIR}/ca.encrypted.key ${NODE1_NAME}:/etc/cloudify/ca_key.pem
  sudo docker exec ${NODE1_NAME} cfy_manager configure -c /etc/cloudify/manager_config.yaml -v
}

function run_manager2(){
  # Prepare Manager 2 on Node2
  sed -e "s/CONTAINER_IP/${MANAGER2_IP}/g" \
      -e "s/QUEUE1_IP/${QUEUE1_IP}/g" \
      -e "s/QUEUE2_IP/${QUEUE2_IP}/g" \
      -e "s/QUEUE3_IP/${QUEUE3_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      manager2_config.yaml > ${TMPDIR}/rendered_manager2_config.yaml
  cat ${TMPDIR}/rendered_manager2_config.yaml
  sudo docker cp ${TMPDIR}/rendered_manager2_config.yaml ${NODE2_NAME}:/etc/cloudify/manager_config.yaml
  sudo docker cp ${TMPDIR}/manager_2_key.pem ${NODE2_NAME}:/etc/cloudify/manager_key.pem
  sudo docker cp ${TMPDIR}/manager_2_cert.pem ${NODE2_NAME}:/etc/cloudify/manager_cert.pem
  sudo docker cp ${TMPDIR}/cloudify.crt ${NODE2_NAME}:/etc/cloudify/manager_postgres_client_cert.pem
  sudo docker cp ${TMPDIR}/cloudify.key ${NODE2_NAME}:/etc/cloudify/manager_postgres_client_key.pem
  sudo docker cp ${TMPDIR}/postgres.crt ${NODE2_NAME}:/etc/cloudify/manager_postgres_su_client_cert.pem
  sudo docker cp ${TMPDIR}/postgres.key ${NODE2_NAME}:/etc/cloudify/manager_postgres_su_client_key.pem
  sudo docker cp ${TMPDIR}/external_key_2.pem ${NODE2_NAME}:/etc/cloudify/manager_external_key.pem
  sudo docker cp ${TMPDIR}/external_cert_2.pem ${NODE2_NAME}:/etc/cloudify/manager_external_cert.pem
  sudo docker cp ${TMPDIR}/prometheus_key_2.pem ${NODE2_NAME}:/etc/cloudify/manager_prometheus_key.pem
  sudo docker cp ${TMPDIR}/prometheus_cert_2.pem ${NODE2_NAME}:/etc/cloudify/manager_prometheus_cert.pem
  sudo docker cp ${TMPDIR}/ca.encrypted.key ${NODE2_NAME}:/etc/cloudify/ca_key.pem
  sudo docker exec ${NODE2_NAME} cfy_manager configure -c /etc/cloudify/manager_config.yaml -v
}

function run_manager3(){
  # Prepare Manager 3 on Node3
  sed -e "s/CONTAINER_IP/${MANAGER3_IP}/g" \
      -e "s/QUEUE1_IP/${QUEUE1_IP}/g" \
      -e "s/QUEUE2_IP/${QUEUE2_IP}/g" \
      -e "s/QUEUE3_IP/${QUEUE3_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      manager3_config.yaml > ${TMPDIR}/rendered_manager3_config.yaml
  cat ${TMPDIR}/rendered_manager3_config.yaml
  sudo docker cp ${TMPDIR}/rendered_manager3_config.yaml ${NODE3_NAME}:/etc/cloudify/manager_config.yaml
  sudo docker cp ${TMPDIR}/manager_3_key.pem ${NODE3_NAME}:/etc/cloudify/manager_key.pem
  sudo docker cp ${TMPDIR}/manager_3_cert.pem ${NODE3_NAME}:/etc/cloudify/manager_cert.pem
  sudo docker cp ${TMPDIR}/cloudify.crt ${NODE3_NAME}:/etc/cloudify/manager_postgres_client_cert.pem
  sudo docker cp ${TMPDIR}/cloudify.key ${NODE3_NAME}:/etc/cloudify/manager_postgres_client_key.pem
  sudo docker cp ${TMPDIR}/postgres.crt ${NODE3_NAME}:/etc/cloudify/manager_postgres_su_client_cert.pem
  sudo docker cp ${TMPDIR}/postgres.key ${NODE3_NAME}:/etc/cloudify/manager_postgres_su_client_key.pem
  sudo docker cp ${TMPDIR}/external_key_3.pem ${NODE3_NAME}:/etc/cloudify/manager_external_key.pem
  sudo docker cp ${TMPDIR}/external_cert_3.pem ${NODE3_NAME}:/etc/cloudify/manager_external_cert.pem
  sudo docker cp ${TMPDIR}/prometheus_key_3.pem ${NODE3_NAME}:/etc/cloudify/manager_prometheus_key.pem
  sudo docker cp ${TMPDIR}/prometheus_cert_3.pem ${NODE3_NAME}:/etc/cloudify/manager_prometheus_cert.pem
  sudo docker cp ${TMPDIR}/ca.encrypted.key ${NODE3_NAME}:/etc/cloudify/ca_key.pem
  sudo docker exec ${NODE3_NAME} cfy_manager configure -c /etc/cloudify/manager_config.yaml -v
}

function main(){
  create_network
  create_certs
  run_queue1
  run_queue2
  run_queue3
  run_db1
  run_db2
  run_db3
  run_manager1
  run_manager2
  run_manager3
  echo "Rendered configs and certs are in ${TMPDIR}"
}
main
