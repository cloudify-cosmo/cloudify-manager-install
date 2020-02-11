function wait_for_container {
    docker exec $1 bash -c 'while supervisorctl status starter | grep -qvE "(EXITED|FAILED)"; do sleep 1; done'
}

function generate_test_cert {
    san=$1
    CONTAINER_ID=$(docker run -d cloudify-manager yes)
    if [ -f "ca.crt" ]
    then
        docker exec ${CONTAINER_ID} mkdir /etc/cloudify/.cloudify-test-ca
        docker cp ca.key ${CONTAINER_ID}:/etc/cloudify/.cloudify-test-ca/ca.key
        docker cp ca.crt ${CONTAINER_ID}:/etc/cloudify/.cloudify-test-ca/ca.crt
    fi
    docker exec ${CONTAINER_ID} cfy_manager generate-test-cert -s $san
    docker cp ${CONTAINER_ID}:/etc/cloudify/.cloudify-test-ca/ca.key ca.key
    docker cp ${CONTAINER_ID}:/etc/cloudify/.cloudify-test-ca/ca.crt ca.crt
    docker cp ${CONTAINER_ID}:/etc/cloudify/.cloudify-test-ca/$san.crt $san.crt
    docker cp ${CONTAINER_ID}:/etc/cloudify/.cloudify-test-ca/$san.key $san.key
    docker rm -f ${CONTAINER_ID}
}
