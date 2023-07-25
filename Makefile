VERSION=1.0.5

release:
	go build -buildmode=pie -ldflags "-X 'github.com/aws/rolesanywhere-credential-helper/cmd.Version=${VERSION}' -linkmode=external -w -s" -trimpath -o build/bin/aws_signing_helper main.go

certsdir=tst/certs
curdir=$(shell pwd)

RSAKEYS := $(foreach keylen, 1024 2048 4096, $(certsdir)/rsa-$(keylen)-key.pem)
ECKEYS := $(foreach curve, prime256v1 secp384r1, $(certsdir)/ec-$(curve)-key.pem)
PKCS8KEYS := $(patsubst %-key.pem,%-key-pkcs8.pem,$(RSAKEYS) $(ECKEYS))
ECCERTS := $(foreach digest, sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(ECKEYS)))
RSACERTS := $(foreach digest, md5 sha1 sha256 sha384 sha512, $(patsubst %-key.pem, %-$(digest)-cert.pem, $(RSAKEYS)))
PKCS12CERTS := $(patsubst %-cert.pem, %.p12, $(RSACERTS) $(ECCERTS))

test: test-certs
	go test -v ./...

%-md5-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed -r 's|.*/([^/]+)-cert.pem|\1|'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -md5
%-sha1-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed -r 's|.*/([^/]+)-cert.pem|\1|'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha1
%-sha256-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed -r 's|.*/([^/]+)-cert.pem|\1|'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha256
%-sha384-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed -r 's|.*/([^/]+)-cert.pem|\1|'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha384
%-sha512-cert.pem: %-key.pem
	SUBJ=$$(echo "$@" | sed -r 's|.*/([^/]+)-cert.pem|\1|'); \
	openssl req -x509 -new -key $< -out $@ -days 10000 -subj "/CN=roles-anywhere-$${SUBJ}" -sha512

# Go PKCS#12 only supports SHA1 and 3DES!!
%.p12: %-pass.p12
	echo Creating $@...
	ls -l $<
	KEY=$$(echo "$@" | sed 's/-[^-]*\.p12/-key.pem/'); \
	CERT=$$(echo "$@" | sed 's/.p12/-cert.pem/'); \
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

$(RSAKEYS):
	KEYLEN=$$(echo "$@" | sed 's/.*rsa-\([0-9]*\)-key.pem/\1/'); \
	openssl genrsa -out $@ $${KEYLEN}

$(ECKEYS):
	CURVE=$$(echo "$@" | sed 's/.*ec-\([^-]*\)-key.pem/\1/'); \
	openssl ecparam -name $${CURVE} -genkey -out $@

$(certsdir)/cert-bundle.pem: $(RSACERTS) $(ECCERTS)
	cat $^ > $@

test-certs: $(PKCS8KEYS) $(RSAKEYS) $(ECKEYS) $(RSACERTS) $(ECCERTS) $(PKCS12CERTS) $(certsdir)/cert-bundle.pem 

test-clean:
	rm -f $(RSAKEYS) $(ECKEYS)
	rm -f $(PKCS8KEYS)
	rm -f $(RSACERTS) $(ECCERTS)
	rm -f $(PKCS12CERTS)
	rm -f $(certsdir)/cert-bundle.pem
