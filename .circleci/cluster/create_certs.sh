#!/usr/bin/env bash

function generate_test_cert {
    san=$1
    docker run --rm  -v $(pwd):/root/.cloudify-test-ca cfy_manager_image_preinstalled cfy_manager generate-test-cert -s $san
}

generate_test_cert $QUEUE_IP
mv $QUEUE_IP.crt queue_cert.pem
mv $QUEUE_IP.key queue_key.pem

generate_test_cert $DB_IP
mv $DB_IP.crt db_cert.pem
mv $DB_IP.key db_key.pem

generate_test_cert $MANAGER1_IP
mv $MANAGER1_IP.crt db_client_1_cert.pem
mv $MANAGER1_IP.key db_client_1_key.pem

generate_test_cert $MANAGER2_IP
mv $MANAGER2_IP.crt db_client_2_cert.pem
mv $MANAGER2_IP.key db_client_2_key.pem
