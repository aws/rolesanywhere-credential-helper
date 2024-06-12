VERSION=1.1.1

.PHONY: release
release: build/bin/aws_signing_helper

build/bin/aws_signing_helper:
	go build -buildmode=pie -ldflags "-X 'github.com/aws/rolesanywhere-credential-helper/cmd.Version=${VERSION}' -linkmode=external -w -s" -trimpath -o build/bin/aws_signing_helper main.go

.PHONY: clean
clean:
	rm -rf build

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

# Software TPM. For generating keys/certs, we run the swtpm in TCP mode,
# because that's what the tools and the OpenSSL ENGINE require. Each of
# the rules which might need the swtpm will ensure that it's running by
# invoking $(START_SWTPM_TCP). The 'user-certs:; rule will then *stop* it
# by running $(STOP_SWTPM_TCP), after all the certs and keys have been
# created.
#
# For the actual test, we need it to run in UNIX socket mode, since
# *that* is all that go-tpm can cope with. So we start it in that mode
# in the 'test:' recipe, and stop it again afterwards.
#
SWTPM_STATEDIR := $(curdir)/tst/swtpm
SWTPM_CTRLSOCK := $(curdir)/tst/swtpm-ctrl
SWTPM_SERVSOCK := $(curdir)/tst/swtpm-serv
SWTPM := swtpm socket --tpm2 --tpmstate dir=$(SWTPM_STATEDIR)

# Annoyingly, while we only support UNIX socket, the ENGINE only supports TCP.
SWTPM_UNIX := --server type=unixio,path=$(SWTPM_SERVSOCK) --ctrl type=unixio,path=$(SWTPM_CTRLSOCK)
SWTPM_NET := --server type=tcp,port=2321 --ctrl type=tcp,port=2322

# Check that the swtpm is running for TCP connections. This isn't a normal
# phony rule because we don't want it running unless there's actually some
# work to be done over the TCP socket (creating keys, certs, etc.).
START_SWTPM_TCP := \
	if ! swtpm_ioctl --tcp 127.0.0.1:2322 -g >/dev/null 2>/dev/null; then \
		mkdir -p $(SWTPM_STATEDIR); \
		$(SWTPM) $(SWTPM_NET) --flags not-need-init,startup-clear -d; \
	fi
STOP_SWTPM_TCP := swtpm_ioctl --tcp 127.0.0.1:2322 -s

# This one is used for the actual test run
START_SWTPM_UNIX := \
	if ! swtpm_ioctl --unix $(SWTPM_CTRLSOCK) -g >/dev/null 2>/dev/null; then \
		$(SWTPM) $(SWTPM_UNIX) --flags not-need-init,startup-clear -d; \
	fi
STOP_SWTPM_UNIX := swtpm_ioctl --unix $(SWTPM_CTRLSOCK) -s

$(certsdir)/tpm-sw-rsa-key.pem:
	$(START_SWTPM_TCP)
	TPM_INTERFACE_TYPE=socsim create_tpm2_key -r $@

$(certsdir)/tpm-sw-ec-prime256-key.pem:
	$(START_SWTPM_TCP)
	TPM_INTERFACE_TYPE=socsim create_tpm2_key -e prime256v1 $@

$(certsdir)/tpm-sw-ec-secp384r1-key.pem:
	$(START_SWTPM_TCP)
	TPM_INTERFACE_TYPE=socsim create_tpm2_key -e secp384r1 $@

# Create a persistent key at 0x81000001 in the owner hierarchiy, if it
# doesn't already exist. And a PEM key with that as its parent.
$(certsdir)/tpm-sw-ec-81000001-key.pem:
	$(START_SWTPM_TCP)
	if ! TPM_INTERFACE_TYPE=socsim tssreadpublic -ho 81000001; then \
		TPM_INTERFACE_TYPE=socsim tsscreateprimary -hi o -rsa && \
		TPM_INTERFACE_TYPE=socsim tssevictcontrol -hi o -ho 80000000 -hp 81000001; \
	fi
	TPM_INTERFACE_TYPE=socsim create_tpm2_key -e prime256v1 -p 81000001 $@

SWTPMKEYS := $(certsdir)/tpm-sw-rsa-key.pem $(certsdir)/tpm-sw-ec-secp384r1-key.pem $(certsdir)/tpm-sw-ec-prime256-key.pem $(certsdir)/tpm-sw-ec-81000001-key.pem
SWTPMCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(SWTPMKEYS)))

HWTPMKEYS := $(certsdir)/tpm-hw-rsa-key.pem $(certsdir)/tpm-hw-ec-key.pem  $(certsdir)/tpm-hw-ec-81000001-key.pem
HWTPMCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(HWTPMKEYS)))

# User can test on hardware TPM with `make TPM_DEVICE=/dev/tpmrm0 test`
ifeq ($(TPM_DEVICE),)
TPM_DEVICE := $(SWTPM_SERVSOCK)
TPMKEYS := $(SWTPMKEYS)
TPMCERTS := $(SWTPMCERTS)
START_SWTPM := $(START_SWTPM_UNIX)
STOP_SWTPM := $(STOP_SWTPM_UNIX)
else
TPMKEYS := $(HWTPMKEYS)
TPMCERTS := $(HWTPMCERTS)
START_SWTPM := true
STOP_SWTPM := true
endif

export TPM_DEVICE



# It's hard to ao a file-based rule for the contents of the SoftHSM token.
# So just populate it as a side-effect of creating the softhsm2.conf file.
tst/softhsm2.conf: tst/softhsm2.conf.template $(PKCS8KEYS) $(RSACERTS) $(ECCERTS) tst/certs/rsa-2048-2-sha256-cert.pem
	rm -rf tst/softhsm/*
	sed 's|@top_srcdir@|${curdir}|g' $< > $@.tmp
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label credential-helper-test \
		--so-pin 12345678 --pin 1234

	$(SHM2_UTIL) --token credential-helper-test --pin 1234 \
		--import $(certsdir)/rsa-2048-key-pkcs8.pem --label rsa-2048 --id 01
	$(P11TOOL) --load-certificate $(certsdir)/rsa-2048-sha256-cert.pem \
		--no-mark-private --label rsa-2048 --id 01 --set-pin 1234 --login \
		--write "pkcs11:token=credential-helper-test;pin-value=1234"

	$(SHM2_UTIL) --token credential-helper-test --pin 1234 \
		--import $(certsdir)/ec-prime256v1-key-pkcs8.pem --label ec-prime256v1 --id 02
	$(P11TOOL) --load-certificate $(certsdir)/ec-prime256v1-sha256-cert.pem \
		--no-mark-private --label ec-prime256v1 --id 02 --set-pin 1234 --login \
		--write "pkcs11:token=credential-helper-test;pin-value=1234"

	$(P11TOOL) --load-privkey $(certsdir)/rsa-2048-key-pkcs8.pem \
		--label rsa-2048-always-auth --id 03 --set-pin 1234 --login \
		--write "pkcs11:token=credential-helper-test;pin-value=1234" \
		--mark-always-authenticate

	$(P11TOOL) --load-privkey $(certsdir)/ec-prime256v1-key-pkcs8.pem \
		--label ec-prime256v1-always-auth --id 04 --set-pin 1234 --login \
		--write "pkcs11:token=credential-helper-test;pin-value=1234" \
		--mark-always-authenticate
	mv $@.tmp $@

.PHONY: test
test: test-certs tst/softhsm2.conf
	$(START_SWTPM)
	SOFTHSM2_CONF=$(curdir)/tst/softhsm2.conf go test -v ./... || :
	$(STOP_SWTPM)

define CERT_RECIPE
	@SUBJ=$$(echo "$@" | sed 's^\(.*/\)\?\([^/]*\)-cert.pem^\2^'); \
	[ "$${SUBJ#tpm-}" != "$${SUBJ}" ] && ENG="--engine tpm2 --keyform engine";  \
	if [ "$${SUBJ#tpm-sw-}" != "$${SUBJ}" ]; then $(START_SWTPM_TCP); export TPM_INTERFACE_TYPE=socsim; fi; \
	echo 	openssl req -x509 -new $${ENG} -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -$${SUBJ##*-}; \
	openssl req -x509 -new $${ENG} -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -$${SUBJ##*-};
endef

%-md5-cert.pem: %-key.pem; $(CERT_RECIPE)
%-sha256-cert.pem: %-key.pem; $(CERT_RECIPE)
%-sha1-cert.pem: %-key.pem; $(CERT_RECIPE)
%-sha384-cert.pem: %-key.pem; $(CERT_RECIPE)
%-sha512-cert.pem: %-key.pem; $(CERT_RECIPE)

%-combo.pem: %-cert.pem
	KEY=$$(echo "$@" | sed 's/-[^-]*-combo.pem/-key.pem/'); \
	cat $${KEY} $< > $@.tmp && mv $@.tmp $@

# Go PKCS#12 only supports SHA1 and 3DES!!
%.p12: %-cert.pem
	KEY=$$(echo "$@" | sed 's/-[^-]*\.p12/-key.pem/'); \
	CERT=$$(echo "$@" | sed 's/.p12/-cert.pem/'); \
	openssl pkcs12 -export -passout pass: -macalg SHA1 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-keypbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-inkey $${KEY} -out "$@" -in $${CERT}

# And once again, it's hard to do a file-based rule for the contents of the certificate store. 
# So just populate it as a side-effect of creating the p12 file.
%-pass.p12: %-cert.pem
	echo Creating $@...
	ls -l $<
	KEY=$$(echo "$@" | sed 's/-[^-]*\-pass.p12/-key.pem/'); \
	openssl pkcs12 -export -passout pass:test -macalg SHA1 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-keypbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-inkey $${KEY} -out "$@" -in "$<"

%-pkcs8.pem: %.pem
	openssl pkcs8 -topk8 -inform PEM -outform PEM -in $< -out $@ -nocrypt

$(certsdir)/tpm-hw-rsa-key.pem:
	create_tpm2_key -r $@

$(certsdir)/tpm-hw-ec-key.pem:
	create_tpm2_key -e prime256v1 $@

$(certsdir)/tpm-hw-ec-81000001-key.pem:
	create_tpm2_key -e prime256v1 -p 81000001 $@

$(RSAKEYS):
	KEYLEN=$$(echo "$@" | sed 's/.*rsa-\([0-9]*\)-key.pem/\1/'); \
	openssl genrsa -out $@ $${KEYLEN}

$(ECKEYS):
	CURVE=$$(echo "$@" | sed 's/.*ec-\([^-]*\)-key.pem/\1/'); \
	openssl ecparam -name $${CURVE} -genkey -out $@

$(certsdir)/cert-bundle.pem: $(RSACERTS) $(ECCERTS)
	cat $^ > $@

$(certsdir)/cert-bundle-with-comments.pem: $(RSACERTS) $(ECCERTS)
	for dep in $^; do \
		cat $$dep >> $@; \
		echo "Comment in bundle\n" >> $@; \
	done

KEYS := $(RSAKEYS) $(ECKEYS) $(TPMKEYS) $(PKCS8KEYS)
CERTS := $(RSACERTS) $(ECCERTS) $(TPMCERTS)
COMBOS := $(patsubst %-cert.pem, %-combo.pem, $(CERTS))

test-certs: $(KEYS) $(CERTS) $(COMBOS) $(PKCS12CERTS) $(certsdir)/cert-bundle.pem tst/softhsm2.conf
	$(STOP_SWTPM_TCP) 2>/dev/null || :

.PHONY: test-certs
test-certs: $(PKCS8KEYS) $(RSAKEYS) $(ECKEYS) $(RSACERTS) $(ECCERTS) $(PKCS12CERTS) $(certsdir)/cert-bundle.pem $(certsdir)/cert-bundle-with-comments.pem tst/softhsm2.conf

.PHONY: test-clean
test-clean:
	rm -f $(RSAKEYS) $(ECKEYS) $(HWTPMKEYS)
	rm -f $(PKCS8KEYS)
	rm -f $(RSACERTS) $(ECCERTS) $(HWTPMCERTS)
	rm -f $(PKCS12CERTS) $(COMBOS)
	rm -f $(certsdir)/cert-bundle.pem
	rm -f $(certsdir)/cert-with-comments.pem
	rm -f tst/softhsm2.conf
	rm -rf tst/softhsm/*
	$(STOP_SWTPM_TCP) || :
	$(STOP_SWTPM_UNIX) || :
	rm -rf $(SWTPMKEYS) $(SWTPMCERTS) tst/swtpm

