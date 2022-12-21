# this script must be sourced from start_cluster.sh
function generate_test_cert {
    san=$1
    docker run --rm  -v $(pwd):/root/.cloudify-test-ca ${IMAGE} cfy_manager generate-test-cert -s $san
}

function generate_certs(){
    generate_test_cert $QUEUE1_IP
    mv $QUEUE1_IP.crt queue1_cert.pem
    mv $QUEUE1_IP.key queue1_key.pem

    generate_test_cert $QUEUE2_IP
    mv $QUEUE2_IP.crt queue2_cert.pem
    mv $QUEUE2_IP.key queue2_key.pem

    generate_test_cert $QUEUE3_IP
    mv $QUEUE3_IP.crt queue3_cert.pem
    mv $QUEUE3_IP.key queue3_key.pem

    generate_test_cert $DB1_IP
    mv $DB1_IP.crt db1_cert.pem
    mv $DB1_IP.key db1_key.pem

    generate_test_cert $DB2_IP
    mv $DB2_IP.crt db2_cert.pem
    mv $DB2_IP.key db2_key.pem

    generate_test_cert $DB3_IP
    mv $DB3_IP.crt db3_cert.pem
    mv $DB3_IP.key db3_key.pem

    # Client cert requires DB user as its CN
    generate_test_cert cloudify

    # Client superuser cert requires DB superuser as its CN
    generate_test_cert postgres

    generate_test_cert $MANAGER1_IP
    mv $MANAGER1_IP.crt external_cert_1.pem
    mv $MANAGER1_IP.key external_key_1.pem

    generate_test_cert $MANAGER2_IP
    mv $MANAGER2_IP.crt external_cert_2.pem
    mv $MANAGER2_IP.key external_key_2.pem

    generate_test_cert $MANAGER3_IP
    mv $MANAGER3_IP.crt external_cert_3.pem
    mv $MANAGER3_IP.key external_key_3.pem

    generate_test_cert $MANAGER1_IP
    mv $MANAGER1_IP.crt manager_1_cert.pem
    mv $MANAGER1_IP.key manager_1_key.pem

    generate_test_cert $MANAGER2_IP
    mv $MANAGER2_IP.crt manager_2_cert.pem
    mv $MANAGER2_IP.key manager_2_key.pem

    generate_test_cert $MANAGER3_IP
    mv $MANAGER3_IP.crt manager_3_cert.pem
    mv $MANAGER3_IP.key manager_3_key.pem

    generate_test_cert $MANAGER2_IP
    mv $MANAGER2_IP.crt prometheus_cert_2.pem
    mv $MANAGER2_IP.key prometheus_key_2.pem

    generate_test_cert $MANAGER3_IP
    mv $MANAGER3_IP.crt prometheus_cert_3.pem
    mv $MANAGER3_IP.key prometheus_key_3.pem

}
