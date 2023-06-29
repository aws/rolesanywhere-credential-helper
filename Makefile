VERSION=1.0.6

release:
	go build -buildmode=pie -ldflags "-X 'github.com/aws/rolesanywhere-credential-helper/cmd.Version=${VERSION}' -linkmode=external -w -s" -trimpath -o build/bin/aws_signing_helper main.go

# Setting up SoftHSM for PKCS#11 tests. 
# This portion is largely copied from https://gitlab.com/openconnect/openconnect/-/blob/v9.12/tests/Makefile.am#L363. 
SHM2_UTIL=SOFTHSM2_CONF=tst/softhsm2.conf softhsm2-util
P11TOOL=SOFTHSM2_CONF=tst/softhsm2.conf p11tool

certsdir=tst/certs
curdir=$(shell pwd)

# Nice and simple: Certs visible without login, public keys present in token. 
softhsm-setup0:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label credential-helper-test \
		--so-pin 12345678 --pin 1234

	$(SHM2_UTIL) --token credential-helper-test --pin 1234 \
		--import $(certsdir)/rsa-2048-key-pkcs8.pem --label RSA --id 01
	$(P11TOOL) --load-certificate $(certsdir)/rsa-2048-sha256-cert.pem \
		--no-mark-private --label RSA --id 01 --set-pin 1234 --login \
		--write "pkcs11:token=credential-helper-test;pin-value=1234"

	$(SHM2_UTIL) --token credential-helper-test --pin 1234 \
		--import $(certsdir)/ec-prime256v1-key-pkcs8.pem --label EC --id 02
	$(P11TOOL) --load-certificate $(certsdir)/ec-prime256v1-sha256-cert.pem \
		--no-mark-private --label EC --id 02 --set-pin 1234 --login \
		--write "pkcs11:token=credential-helper-test;pin-value=1234"

test: softhsm-setup0
	SOFTHSM2_CONF=$(curdir)/tst/softhsm2.conf go test -v ./...
