#!/usr/bin/env bash

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -batch \
    -days 3650 \
    -out ca_cert.pem \
    -keyout ca_key.pem \
    -config .circleci/cluster/ca_config

sed -e "s/CONTAINER_IP/${QUEUE_IP}/g" .circleci/cluster/csr_config.template > queue_cert_config
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -batch \
    -sha256 \
    -config queue_cert_config \
    -out queue_cert.csr \
    -keyout queue_key.pem
openssl x509 \
    -days 3650 \
    -sha256 \
    -req \
    -in queue_cert.csr \
    -out queue_cert.pem \
    -extensions v3_ext \
    -extfile queue_cert_config \
    -CA ca_cert.pem \
    -CAkey ca_key.pem \
    -CAcreateserial


sed -e "s/CONTAINER_IP/${DB_IP}/g" .circleci/cluster/csr_config.template > db_cert_config
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -batch \
    -sha256 \
    -config db_cert_config \
    -out db_cert.csr \
    -keyout db_key.pem
openssl x509 \
    -days 3650 \
    -sha256 \
    -req \
    -in db_cert.csr \
    -out db_cert.pem \
    -extensions v3_ext \
    -extfile db_cert_config \
    -CA ca_cert.pem \
    -CAkey ca_key.pem \
    -CAcreateserial


sed -e "s/CONTAINER_IP/${MANAGER1_IP}/g" .circleci/cluster/csr_config.template > db_client_1_cert_config
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -batch \
    -sha256 \
    -config db_client_1_cert_config \
    -out db_client_1.csr \
    -keyout db_client_1_key.pem
openssl x509 \
    -days 3650 \
    -sha256 \
    -req \
    -in db_client_1.csr \
    -out db_client_1_cert.pem \
    -extensions v3_ext \
    -extfile db_client_1_cert_config \
    -CA ca_cert.pem \
    -CAkey ca_key.pem \
    -CAcreateserial


sed -e "s/CONTAINER_IP/${MANAGER1_IP}/g" .circleci/cluster/csr_config.template > db_client_2_cert_config
openssl req \
    -newkey rsa:2048 \
    -nodes \
    -batch \
    -sha256 \
    -config db_client_2_cert_config \
    -out db_client_2.csr \
    -keyout db_client_2_key.pem
openssl x509 \
    -days 3650 \
    -sha256 \
    -req \
    -in db_client_2.csr \
    -out db_client_2_cert.pem \
    -extensions v3_ext \
    -extfile db_client_2_cert_config \
    -CA ca_cert.pem \
    -CAkey ca_key.pem \
    -CAcreateserial
