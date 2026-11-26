//go:build windows

package aws_signing_helper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// exportCertContext must not return a certificate that aliases the context's memory,
// which Windows releases when the context is freed or the store is closed.
func TestExportCertContextCopiesEncodedCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "exportCertContext test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	// Stand-in for the buffer a CERT_CONTEXT points to.
	encoded := bytes.Clone(der)
	certCtx := &windows.CertContext{
		EncodingType: windows.X509_ASN_ENCODING,
		EncodedCert:  &encoded[0],
		Length:       uint32(len(encoded)),
	}

	cert, err := exportCertContext(certCtx)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the context's memory being released and reused.
	for i := range encoded {
		encoded[i] = 0
	}

	if !bytes.Equal(cert.Raw, der) {
		t.Fatal("certificate Raw changed after the context's buffer was overwritten")
	}
}
