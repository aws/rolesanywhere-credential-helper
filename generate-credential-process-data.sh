#!/bin/bash

# Simple script to generate a CA certificate/private key
# and end-entity certificate/private key for use with 
# Roles Anywhere

set -exuo pipefail

script=$(readlink -f "$0")
basedir=$(dirname "$script")
data_folder=${basedir}/credential-process-data

# Create root CA config file
cat > ${data_folder}/root.conf << EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = TEST ROOT

[ v3 ]
basicConstraints = critical,CA:TRUE,pathlen:1
subjectKeyIdentifier = hash
keyUsage = critical, cRLSign, digitalSignature, keyCertSign
authorityKeyIdentifier = keyid:always,issuer:always
EOF

# Create root CA certificate and RSA private key
openssl req -config ${data_folder}/root.conf -days 365 -extensions v3 -keyout ${data_folder}/root-key.pem -newkey rsa:2048 -nodes -out ${data_folder}/root-cert.pem -set_serial 1 -sha256 -x509

# Create client certificate config file
cat > ${data_folder}/client.conf <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no
default_bits = 2048
default_md = sha256

[ req_distinguished_name ]
CN = TEST CLIENT

[ v3 ]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
EOF

# Create client certificate and RSA private key
openssl req -nodes -new -keyout ${data_folder}/client-key.pem -out ${data_folder}/client-csr.pem -config ${data_folder}/client.conf
openssl x509 -req -in ${data_folder}/client-csr.pem -CA ${data_folder}/root-cert.pem -CAkey ${data_folder}/root-key.pem -set_serial 2 -out ${data_folder}/client-cert.pem -days 365 -sha256 -extfile ${data_folder}/client.conf -extensions v3
