VERSION=1.7.0

.PHONY: release
release: build/bin/aws_signing_helper

curdir=$(shell pwd)
uname=$(shell uname -s)
ifeq ($(uname),Darwin)
	extra_ld_flags=-extldflags '-sectcreate __TEXT __info_plist $(curdir)/Info.plist'
else
	extra_ld_flags=
endif

build/bin/aws_signing_helper:
	go build -buildmode=pie -ldflags "-X 'github.com/aws/rolesanywhere-credential-helper/cmd.Version=${VERSION}' $(extra_ld_flags) -linkmode=external -w -s" -trimpath -o build/bin/aws_signing_helper main.go

.PHONY: clean
clean: test-clean
	rm -rf build

# Setting up SoftHSM for PKCS#11 tests. 
# This portion is largely copied from https://gitlab.com/openconnect/openconnect/-/blob/v9.12/tests/Makefile.am#L363. 
SHM2_UTIL=SOFTHSM2_CONF=tst/softhsm2.conf.tmp softhsm2-util
P11TOOL=SOFTHSM2_CONF=tst/softhsm2.conf.tmp p11tool

certsdir=tst/certs

PKCS8_OPENSSL_CMD = openssl pkcs8 -topk8 -inform PEM -outform PEM -in $< -out $@ -passout pass:password

RSAKEYS := $(foreach keylen, 1024 2048 4096, $(certsdir)/rsa-$(keylen)-key.pem)
ECKEYS := $(foreach curve, prime256v1 secp384r1, $(certsdir)/ec-$(curve)-key.pem)
PKCS8KEYS := $(patsubst %-key.pem,%-key-pkcs8.pem,$(RSAKEYS) $(ECKEYS))
PKCS8ENCRYPTEDKEYS := $(patsubst %.pem, %-pkcs8-scrypt.pem, $(RSAKEYS) $(ECKEYS)) \
	$(foreach prf, hmacWithSHA256 hmacWithSHA384 hmacWithSHA512, \
		$(patsubst %.pem, %-pkcs8-$(prf).pem, $(RSAKEYS) $(ECKEYS))) \
	$(foreach algo, aes-128-cbc aes-192-cbc aes-256-cbc, \
		$(patsubst %.pem, %-pkcs8-$(subst -,,$(algo)).pem, $(RSAKEYS) $(ECKEYS)))
ECCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(ECKEYS)))
RSACERTS := $(foreach digest, md5 sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(RSAKEYS)))
PKCS12CERTS := $(patsubst %-cert.pem, %.p12, $(RSACERTS) $(ECCERTS))

# Rules for converting a .pem private key to an encrypted PKCS#8 format using different
# encryption schemes or key derivation functions (e.g., HMAC with SHA algorithms, AES-CBC, scrypt).
%-pkcs8-hmacWithSHA256.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -v2prf hmacWithSHA256

%-pkcs8-hmacWithSHA384.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -v2prf hmacWithSHA384

%-pkcs8-hmacWithSHA512.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -v2prf hmacWithSHA512

%-pkcs8-aes128cbc.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -v2 aes-128-cbc

%-pkcs8-aes192cbc.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -v2 aes-192-cbc

%-pkcs8-aes256cbc.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -v2 aes-256-cbc

%-pkcs8-scrypt.pem: %.pem
	$(PKCS8_OPENSSL_CMD) -scrypt

# Software TPM. For generating keys/certs, we run the swtpm in TCP mode,
# because that's what the tools and the OpenSSL ENGINE require. Each of
# the rules which might need the swtpm will ensure that it's running by
# invoking $(START_SWTPM_TCP). The 'test-certs:; rule will then *stop* it
# by running $(STOP_SWTPM_TCP), after all the certs and keys have been
# created.
#
# For the actual test, we need it to run in UNIX socket mode, since
# *that* is all that go-tpm can cope with. So we start it in that mode
# in the 'test:' (or 'test-tpm-signer:') recipe(s), and stop it again 
# afterwards.
SWTPM_STATEDIR := $(curdir)/tst/swtpm
SWTPM_CTRLSOCK := $(curdir)/tst/swtpm-ctrl
SWTPM_SERVSOCK := $(curdir)/tst/swtpm-serv
SWTPM := swtpm socket --tpm2 --tpmstate dir=$(SWTPM_STATEDIR)
TABRMD_NAME := com.intel.tss2.Tabrmd2321

# Annoyingly, while we only support UNIX socket, the ENGINE only supports TCP.
SWTPM_UNIX := --server type=unixio,path=$(SWTPM_SERVSOCK) --ctrl type=unixio,path=$(SWTPM_CTRLSOCK)
SWTPM_NET := --server type=tcp,port=2321 --ctrl type=tcp,port=2322

SWTPM_PREFIX := TPM2TOOLS_TCTI=tabrmd:bus_name="$(TABRMD_NAME)",bus_type=session \
		TPM2OPENSSL_TCTI=tabrmd:bus_name="$(TABRMD_NAME)",bus_type=session

# Check that the swtpm is running for TCP connections. This isn't a normal
# phony rule because we don't want it running unless there's actually some
# work to be done over the TCP socket (creating keys, certs, etc.).
START_SWTPM_TCP := \
	if ! swtpm_ioctl --tcp 127.0.0.1:2322 -g >/dev/null 2>/dev/null; then \
		mkdir -p $(SWTPM_STATEDIR); \
		$(SWTPM) $(SWTPM_NET) --flags not-need-init,startup-clear -d; \
		( tpm2-abrmd --session --dbus-name="$(TABRMD_NAME)" --tcti "swtpm:host=localhost,port=2321" & ); \
		$(SWTPM_PREFIX) tpm2_dictionarylockout -s -t 0; \
	fi
STOP_SWTPM_TCP := swtpm_ioctl --tcp 127.0.0.1:2322 -s && kill $$(pgrep tpm2-abrmd)

# This one is used for the actual test run
START_SWTPM_UNIX := \
	if ! swtpm_ioctl --unix $(SWTPM_CTRLSOCK) -g >/dev/null 2>/dev/null; then \
		$(SWTPM) $(SWTPM_UNIX) --flags not-need-init,startup-clear -d; \
	fi
STOP_SWTPM_UNIX := swtpm_ioctl --unix $(SWTPM_CTRLSOCK) -s

$(certsdir)/tpm-sw-rsa-key.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) ./create_tpm2_key.sh -r $@

$(certsdir)/tpm-sw-rsa-key-with-pw.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) ./create_tpm2_key.sh -r -k 1234 $@

$(certsdir)/tpm-sw-ec-prime256-key.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) ./create_tpm2_key.sh -e prime256v1 $@

$(certsdir)/tpm-sw-ec-prime256-key-with-pw.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) ./create_tpm2_key.sh -e prime256v1 -k 1234 $@

$(certsdir)/tpm-sw-ec-secp384r1-key.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) ./create_tpm2_key.sh -e secp384r1 $@

$(certsdir)/tpm-sw-ec-secp384r1-key-with-pw.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) ./create_tpm2_key.sh -e secp384r1 -k 1234 $@

$(certsdir)/tpm-sw-loaded-81000101-ec-secp384r1-key.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) tpm2_createprimary -c parent.ctx
	$(SWTPM_PREFIX) tpm2_create -C parent.ctx -u child.pub -r child.priv
	$(SWTPM_PREFIX) tpm2_load -C parent.ctx -u child.pub -r child.priv -c child.ctx
	$(SWTPM_PREFIX) tpm2_evictcontrol -c child.ctx 0x81000101
	rm parent.ctx child.pub child.priv child.ctx

$(certsdir)/tpm-sw-loaded-81000102-ec-secp384r1-key-with-pw.pem:
	$(START_SWTPM_TCP)
	$(SWTPM_PREFIX) tpm2_createprimary -c parent.ctx
	$(SWTPM_PREFIX) tpm2_create -C parent.ctx -u child.pub -r child.priv -p 1234
	$(SWTPM_PREFIX) tpm2_load -C parent.ctx -u child.pub -r child.priv -c child.ctx
	$(SWTPM_PREFIX) tpm2_evictcontrol -c child.ctx 0x81000102
	rm parent.ctx child.pub child.priv child.ctx

# Create a persistent key at 0x81000001 in the owner hierarchy, if it
# doesn't already exist. And a PEM key with that as its parent.
$(certsdir)/tpm-sw-ec-81000001-key.pem:
	$(START_SWTPM_TCP)
	if ! $(SWTPM_PREFIX) tpm2_readpublic -c 0x81000001; then \
		$(SWTPM_PREFIX) tpm2_createprimary -G rsa -c parent.ctx && \
		$(SWTPM_PREFIX) tpm2_evictcontrol -c parent.ctx 0x81000001; \
	fi
	$(SWTPM_PREFIX) openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:prime256v1 -pkeyopt parent:0x81000001 -out $@

$(certsdir)/tpm-sw-ec-81000001-key-with-pw.pem:
	$(START_SWTPM_TCP)
	if ! $(SWTPM_PREFIX) tpm2_readpublic -c 0x81000001; then \
		$(SWTPM_PREFIX) tpm2_createprimary -G rsa -c parent.ctx && \
		$(SWTPM_PREFIX) tpm2_evictcontrol -c parent.ctx 0x81000001; \
	fi
	$(SWTPM_PREFIX) openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:prime256v1 -pkeyopt parent:0x81000001 -pkeyopt user-auth:1234 -out $@

# Create RSA keys with the Sign capability
$(certsdir)/tpm-sw-rsa-81000001-sign-key.pem:
	if ! $(SWTPM_PREFIX) tpm2_readpublic -c 0x81000001; then \
		$(SWTPM_PREFIX) tpm2_createprimary -G rsa -c parent.ctx && \
		$(SWTPM_PREFIX) tpm2_evictcontrol -c parent.ctx 0x81000001; \
	fi
	$(SWTPM_PREFIX) openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt parent:0x81000001 -out $@

$(certsdir)/tpm-sw-rsa-81000001-sign-key-with-pw.pem: 
	if ! $(SWTPM_PREFIX) tpm2_readpublic -c 0x81000001; then \
		$(SWTPM_PREFIX) tpm2_createprimary -G rsa -c parent.ctx && \
		$(SWTPM_PREFIX) tpm2_evictcontrol -c parent.ctx 0x81000001; \
	fi
	$(SWTPM_PREFIX) openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt parent:0x81000001 -pkeyopt user-auth:1234 -out $@

SWTPM_LOADED_KEYS_WO_PW := $(certsdir)/tpm-sw-loaded-81000101-ec-secp384r1-key.pem
SWTPM_LOADED_KEYS_W_PW := $(certsdir)/tpm-sw-loaded-81000102-ec-secp384r1-key-with-pw.pem 
SWTPMKEYS_WO_PW_WO_SIGN_CAP := $(certsdir)/tpm-sw-rsa-key.pem
SWTPMKEYS_WO_PW := $(certsdir)/tpm-sw-ec-secp384r1-key.pem $(certsdir)/tpm-sw-ec-prime256-key.pem $(certsdir)/tpm-sw-rsa-81000001-sign-key.pem
SWTPMKEYS_W_PW := $(patsubst %.pem, %-with-pw.pem, $(SWTPMKEYS_WO_PW)) $(certsdir)/tpm-sw-ec-81000001-key.pem $(certsdir)/tpm-sw-ec-81000001-key-with-pw.pem $(certsdir)/tpm-sw-rsa-81000001-sign-key-with-pw.pem
SWTPMKEYS := $(SWTPMKEYS_WO_PW) $(SWTPMKEYS_W_PW) $(SWTPMKEYS_WO_PW_WO_SIGN_CAP)
SWTPM_LOADED_KEY_CERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(SWTPM_LOADED_KEYS_WO_PW)))
SWTPMCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(SWTPMKEYS_WO_PW)))

HWTPMKEYS_WO_PW := $(certsdir)/tpm-hw-rsa-key.pem $(certsdir)/tpm-hw-ec-key.pem  $(certsdir)/tpm-hw-ec-81000001-key.pem
HWTPMKEYS_W_PW := $(patsubst %.pem, %-with-pw.pem, $(HWTPMKEYS_WO_PW))
HWTPMKEYS := $(HWTPMKEYS_WO_PW) $(HWTPMKEYS_W_PW)
HWTPMCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(HWTPMKEYS_WO_PW)))

# User can test on hardware TPM with `make TPM_DEVICE=/dev/tpmrm0 test`
ifeq ($(TPM_DEVICE),)
TPM_DEVICE := $(SWTPM_SERVSOCK)
TPMKEYS := $(SWTPMKEYS)
TPMCERTS := $(SWTPMCERTS)
TPMLOADEDKEY_CERTS := $(SWTPM_LOADED_KEY_CERTS)
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
tst/softhsm2.conf: tst/softhsm2.conf.template $(PKCS8KEYS) $(RSACERTS) $(ECCERTS)
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

.PHONY: test-all
test-all: test-all-certs tst/softhsm2.conf
	$(START_SWTPM)
	SOFTHSM2_CONF=$(curdir)/tst/softhsm2.conf go test -v ./... || :
	$(STOP_SWTPM)

TPMCOMBOS := $(patsubst %-cert.pem, %-combo.pem, $(TPMCERTS))

.PHONY: test-tpm-signer
test-tpm-signer: $(certsdir)/cert-bundle.pem $(TPMKEYS) $(TPMCERTS) $(TPMLOADEDKEY_CERTS) $(TPMCOMBOS)
	$(STOP_SWTPM_TCP) 2>/dev/null || :
	$(START_SWTPM)
	go test ./... -run "TPM"
	$(STOP_SWTPM)

.PHONY: test
test: test-certs
	go test ./... -list . | grep -E '^Test[a-zA-Z0-9]+' | grep -vE 'TPMSigner|PKCS11Signer' | tr '\n' '|' | sed 's/|$$//' | xargs -t go test ./... -run

define CERT_RECIPE
	@SUBJ=$$(echo "$@" | sed 's/.*\/\([^/]*\)-cert\.pem/\1/'); \
	[ "$${SUBJ#tpm-}" != "$${SUBJ}" ] && ENG="-provider tpm2 -provider default -propquery '?provider=tpm2'";  \
	if [ "$${SUBJ#tpm-sw-}" != "$${SUBJ}" ]; then $(START_SWTPM_TCP); TPM_PREFIX="$(SWTPM_PREFIX)"; fi; \
	if echo $< | grep -q "loaded"; then KEY=handle:0x$(word 4, $(subst -, , $<)); else KEY=$<; fi; \
	echo 	$${TPM_PREFIX} openssl req -x509 -new $${ENG} -key $${KEY} -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -$${SUBJ##*-}; \
	eval $${TPM_PREFIX} openssl req -x509 -new $${ENG} -key $${KEY} -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -$${SUBJ##*-};
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
	CERT=$$(echo "$@" | sed 's/\.p12/-cert.pem/'); \
	openssl pkcs12 -export -passout pass: -macalg SHA1 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-keypbe pbeWithSHA1And3-KeyTripleDES-CBC \
		-inkey $${KEY} -out "$@" -in $${CERT}

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
	./create_tpm2_key.sh -r $@

$(certsdir)/tpm-hw-rsa-key-with-pw.pem:
	./create_tpm2_key.sh -r -k 1234 $@

$(certsdir)/tpm-hw-ec-key.pem:
	./create_tpm2_key.sh -e prime256v1 $@

$(certsdir)/tpm-hw-ec-key-with-pw.pem:
	./create_tpm2_key.sh -e prime256v1 -k 1234 $@

$(certsdir)/tpm-hw-ec-81000001-key.pem:
	if ! tpm2_readpublic -c 0x81000001; then \
		tpm2_createprimary -G rsa -c parent.ctx && \
		tpm2_evictcontrol -c parent.ctx 0x81000001; \
	fi
	openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:prime256v1 -pkeyopt parent:0x81000001 -out $@

$(certsdir)/tpm-hw-ec-81000001-key.pem:
	if ! tpm2_readpublic -c 0x81000001; then \
		tpm2_createprimary -G rsa -c parent.ctx && \
		tpm2_evictcontrol -c parent.ctx 0x81000001; \
	fi
	openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:prime256v1 -pkeyopt parent:0x81000001 -pkeyopt user-auth:1234 -out $@

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

KEYS := $(RSAKEYS) $(ECKEYS) $(PKCS8KEYS) $(PKCS8ENCRYPTEDKEYS)
ALL_KEYS := $(KEYS) $(TPMKEYS)
CERTS := $(RSACERTS) $(ECCERTS)
ALL_CERTS := $(CERTS) $(TPMCERTS)
COMBOS := $(patsubst %-cert.pem, %-combo.pem, $(CERTS))
ALL_COMBOS := $(patsubst %-cert.pem, %-combo.pem, $(ALL_CERTS))

.PHONY: test-all-certs
test-all-certs: $(ALL_KEYS) $(ALL_CERTS) $(ALL_COMBOS) $(PKCS12CERTS) $(certsdir)/cert-bundle.pem $(certsdir)/cert-bundle-with-comments.pem tst/softhsm2.conf
	$(STOP_SWTPM_TCP) 2>/dev/null || :

.PHONY: test-certs
test-certs: $(KEYS) $(CERTS) $(COMBOS) $(PKCS12CERTS) $(certsdir)/cert-bundle.pem $(certsdir)/cert-bundle-with-comments.pem

.PHONY: test-clean
test-clean:
	rm -f $(RSAKEYS) $(ECKEYS) $(HWTPMKEYS)
	rm -f $(PKCS8KEYS) $(PKCS8ENCRYPTEDKEYS)
	rm -f $(RSACERTS) $(ECCERTS) $(HWTPMCERTS)
	rm -f $(PKCS12CERTS) $(COMBOS)
	rm -f $(certsdir)/cert-bundle.pem
	rm -f $(certsdir)/cert-with-comments.pem
	rm -f tst/softhsm2.conf
	rm -rf tst/softhsm/*
	$(STOP_SWTPM_TCP) || :
	$(STOP_SWTPM_UNIX) || :
	rm -rf $(SWTPMKEYS) $(SWTPMCERTS) $(SWTPM_TMPKEYS) $(SWTPM_STATEDIR)

