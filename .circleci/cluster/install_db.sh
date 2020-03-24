#!/usr/bin/env bash
set -eux


function run_db_container(){
    _ipvar="DB$1_IP"
    _namevar="DB$1_NAME"
    CURRENT_IP="${!_ipvar}"
    CURRENT_NAME="${!_namevar}"
    CERT_FILENAME=db$1_cert.pem
    KEY_FILENAME=db$1_key.pem

    sed -e "s/CONTAINER_IP/${CURRENT_IP}/g" \
      -e "s/DB1_IP/${DB1_IP}/g" \
      -e "s/DB2_IP/${DB2_IP}/g" \
      -e "s/DB3_IP/${DB3_IP}/g" \
      .circleci/cluster/db_config.yaml > db_config.yaml

    docker cp db_config.yaml ${CURRENT_NAME}:/etc/cloudify/config.yaml
    docker cp $CERT_FILENAME ${CURRENT_NAME}:/etc/cloudify/cert.pem
    docker cp $KEY_FILENAME ${CURRENT_NAME}:/etc/cloudify/key.pem
    docker cp ca.crt ${CURRENT_NAME}:/etc/cloudify/ca.pem
    docker exec ${CURRENT_NAME} cfy_manager install --verbose
}

for i in $(seq 1 3); do
    run_db_container $i
done
