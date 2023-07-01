VERSION=1.0.6

release:
	go build -buildmode=pie -ldflags "-X 'github.com/aws/rolesanywhere-credential-helper/cmd.Version=${VERSION}' -linkmode=external -w -s" -trimpath -o build/bin/aws_signing_helper main.go

# Setting up SoftHSM for PKCS#11 tests. 
# This portion is largely copied from https://gitlab.com/openconnect/openconnect/-/blob/v9.12/tests/Makefile.am#L363. 
SHM2_UTIL=SOFTHSM2_CONF=tst/softhsm2.conf.tmp softhsm2-util
P11TOOL=SOFTHSM2_CONF=tst/softhsm2.conf.tmp p11tool

certsdir=tst/certs
curdir=$(shell pwd)

RSAKEYS := $(foreach keylen, 1024 2048 4096, $(certsdir)/rsa-$(keylen)-key.pem)
ECKEYS := $(foreach curve, prime256v1 secp384r1, $(certsdir)/ec-$(curve)-key.pem)
PKCS8KEYS := $(patsubst %-key.pem,%-key-pkcs8.pem,$(RSAKEYS) $(ECKEYS))
ECCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(ECKEYS)))
RSACERTS := $(foreach digest, md5 sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(RSAKEYS)))
PKCS12CERTS := $(patsubst %-cert.pem, %.p12, $(RSACERTS) $(ECCERTS))

# It's hard to ao a file-based rule for the contents of the SoftHSM token.
# So just populate it as a side-effect of creating the softhsm2.conf file.
tst/softhsm2.conf: tst/softhsm2.conf.template $(PKCS8KEYS) $(RSACERTS) $(ECCERTS)
	rm -rf tst/softhsm/*
	sed 's|@top_srcdir@|${curdir}|g' $< > $@.tmp
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
	mv $@.tmp $@

test: test-certs tst/softhsm2.conf
	SOFTHSM2_CONF=$(curdir)/tst/softhsm2.conf go test -v ./...

%-md5-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed 's^\(.*/\)\?\([^/]*\)-cert.pem^\2^'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -md5
%-sha1-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed 's^\(.*/\)\?\([^/]*\)-cert.pem^\2^'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha1
%-sha256-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed 's^\(.*/\)\?\([^/]*\)-cert.pem^\2^'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha256
%-sha384-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed 's^\(.*/\)\?\([^/]*\)-cert.pem^\2^'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha384
%-sha512-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed 's^\(.*/\)\?\([^/]*\)-cert.pem^\2^'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha512

# Go PKCS#12 only supports SHA1 and 3DES!!
%.p12: %-cert.pem
	echo Creating $@...
	ls -l $<
	KEY=$$(echo "$@" | sed 's/-[^-]*\.p12/-key.pem/'); \
	openssl pkcs12 -export -passout pass: -macalg SHA1 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-keypbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-inkey $${KEY} -out "$@" -in "$<"

%-pkcs8.pem: %.pem
	openssl pkcs8 -topk8 -inform PEM -outform PEM -in $< -out $@ -nocrypt


$(RSAKEYS):
	KEYLEN=$$(echo "$@" | sed 's/.*rsa-\([0-9]*\)-key.pem/\1/'); \
	openssl genrsa -out $@ $${KEYLEN}

$(ECKEYS):
	CURVE=$$(echo "$@" | sed 's/.*ec-\([^-]*\)-key.pem/\1/'); \
	openssl ecparam -name $${CURVE} -genkey -out $@

$(certsdir)/cert-bundle.pem: $(RSACERTS) $(ECCERTS)
	cat $^ > $@

test-certs: $(PKCS8KEYS) $(RSAKEYS) $(ECKEYS) $(RSACERTS) $(ECCERTS) $(PKCS12CERTS) $(certsdir)/cert-bundle.pem tst/softhsm2.conf

test-clean:
	rm -f $(RSAKEYS) $(ECKEYS)
	rm -f $(PKCS8KEYS)
	rm -f $(RSACERTS) $(ECCERTS)
	rm -f $(PKCS12CERTS)
	rm -f $(certsdir)/cert-bundle.pem
	rm -f tst/softhsm2.conf
	rm -rf tst/softhsm/*
