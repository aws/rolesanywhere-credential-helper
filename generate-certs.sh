#!/bin/bash

# Simple script to generate key/digest permutations for testing
# keys are shared across certificates with the same algorithm,
# but different digests

ec_digests="sha1 sha256 sha384 sha512"
ec_curves="prime256v1 secp384r1"

rsa_digests="md5 sha1 sha256 sha384 sha512"
rsa_key_lengths="1024 2048 4096"

script=$(readlink -f "$0")
basedir=$(dirname "$script")

for c in $ec_curves; do
	key_file="${basedir}/tst/certs/ec-${c}-key.pem"
	openssl ecparam -name $c -genkey -out $key_file
	for d in $ec_digests; do
		cert_file="${basedir}/tst/certs/ec-${c}-${d}-cert.pem"
		openssl req -x509 -new \
			-key $key_file \
			-out $cert_file \
			-days 365 \
			-subj "/CN=roles-anywhere-${c}-${d}" \
			-${d}
		openssl pkcs12 -export -passout pass: -macalg SHA1 \
			-certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
			-keypbe pbeWithSHA1And3-KeyTripleDES-CBC \
			-out "${basedir}/tst/certs/ec-${c}-${d}.p12" \
			-inkey "${basedir}/tst/certs/ec-${c}-key.pem" \
			-in "${basedir}/tst/certs/ec-${c}-${d}-cert.pem"
	done;
        openssl pkcs8 -topk8 -inform PEM -outform PEM \
            -in ${basedir}/tst/certs/ec-${c}-key.pem \
            -out ${basedir}/tst/certs/ec-${c}-key-pkcs8.pem \
            -nocrypt
done;

for l in $rsa_key_lengths; do
	key_file="${basedir}/tst/certs/rsa-${l}-key.pem"
	openssl genrsa -out $key_file $l
	for d in $rsa_digests; do
		cert_file="${basedir}/tst/certs/rsa-${l}-${d}-cert.pem"
		openssl req -x509 -new \
			-key $key_file \
			-out $cert_file \
			-days 365 \
			-subj "/CN=roles-anywhere-rsa-${l}"
		openssl pkcs12 -export -passout pass: -macalg SHA1 \
			-certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
			-keypbe pbeWithSHA1And3-KeyTripleDES-CBC \
			-out "${basedir}/tst/certs/rsa-${l}-${d}.p12" \
			-inkey "${basedir}/tst/certs/rsa-${l}-key.pem" \
			-in "${basedir}/tst/certs/rsa-${l}-${d}-cert.pem"
	done;
        openssl pkcs8 -topk8 -inform PEM -outform PEM \
            -in ${basedir}/tst/certs/rsa-${l}-key.pem \
            -out ${basedir}/tst/certs/rsa-${l}-key-pkcs8.pem \
            -nocrypt
done;

# Create certificate bundle
cp ${basedir}/tst/certs/rsa-2048-sha256-cert.pem ${basedir}/tst/certs/cert-bundle.pem
cat ${basedir}/tst/certs/ec-prime256v1-sha256-cert.pem >> ${basedir}/tst/certs/cert-bundle.pem
