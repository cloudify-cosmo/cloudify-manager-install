#!/usr/bin/env bash

function generate_test_cert {
    san=$1
    docker run --rm  -v $(pwd):/root/.cloudify-test-ca cfy_manager_image_preinstalled cfy_manager generate-test-cert -s $san
}

generate_test_cert $QUEUE1_IP
mv $QUEUE1_IP.crt queue1_cert.pem
mv $QUEUE1_IP.key queue1_key.pem

generate_test_cert $QUEUE2_IP
mv $QUEUE2_IP.crt queue2_cert.pem
mv $QUEUE2_IP.key queue2_key.pem

generate_test_cert $DB1_IP
mv $DB1_IP.crt db1_cert.pem
mv $DB1_IP.key db1_key.pem

generate_test_cert $DB2_IP
mv $DB2_IP.crt db2_cert.pem
mv $DB2_IP.key db2_key.pem

generate_test_cert $DB3_IP
mv $DB3_IP.crt db3_cert.pem
mv $DB3_IP.key db3_key.pem

generate_test_cert $MANAGER1_IP
mv $MANAGER1_IP.crt db_client_1_cert.pem
mv $MANAGER1_IP.key db_client_1_key.pem

generate_test_cert $MANAGER2_IP
mv $MANAGER2_IP.crt db_client_2_cert.pem
mv $MANAGER2_IP.key db_client_2_key.pem

generate_test_cert $MANAGER1_IP
mv $MANAGER1_IP.crt external_cert_1.pem
mv $MANAGER1_IP.key external_key_1.pem

generate_test_cert $MANAGER2_IP
mv $MANAGER2_IP.crt external_cert_2.pem
mv $MANAGER2_IP.key external_key_2.pem

generate_test_cert $MANAGER1_IP
mv $MANAGER1_IP.crt manager_1_cert.pem
mv $MANAGER1_IP.key manager_1_key.pem

generate_test_cert $MANAGER2_IP
mv $MANAGER2_IP.crt prometheus_cert_2.pem
mv $MANAGER2_IP.key prometheus_key_2.pem
