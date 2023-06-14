package aws_signing_helper

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"

	tpm2 "github.com/google/go-tpm/tpm2"
)

type tpm2_TPMPolicy struct {
	CommandCode   int    `asn1:"explicit,tag:0"`
	CommandPolicy []byte `asn1:"explicit,tag:1"`
}

type tpm2_TPMAuthPolicy struct {
	Name   string           `asn1:"utf8,optional,explicit,tag:0"`
	Policy []tpm2_TPMPolicy `asn1:explicit,tag:1"`
}

type tpm2_TPMKey struct {
	Oid        asn1.ObjectIdentifier
	EmptyAuth  bool                 `asn1:"optional,explicit,tag:0"`
	Policy     []tpm2_TPMPolicy     `asn1:"optional,explicit,tag:1"`
	Secret     []byte               `asn1:"optional,explicit,tag:2"`
	AuthPolicy []tpm2_TPMAuthPolicy `asn1:"optional,explicit,tag:3"`
	Parent     int
	Pubkey     []byte
	Privkey    []byte
}

var oidLoadableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

type TPMv2Signer struct {
	cert      *x509.Certificate
	certChain []*x509.Certificate
	tpmData   tpm2_TPMKey
	public    tpm2.Public
	private   []byte
}

func handleIsPersistent(h int) bool {
	return (h >> 24) == int(tpm2.HandleTypePersistent)
}

// Returns the public key associated with this TPMv2Signer
func (tpmv2Signer *TPMv2Signer) Public() crypto.PublicKey {
	ret, _ := tpmv2Signer.public.Key()
	return ret
}

// Closes this TPMv2Signer
func (tpmv2Signer *TPMv2Signer) Close() {
}

// Implements the crypto.Signer interface and signs the passed in digest
func (tpmv2Signer *TPMv2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, errors.New("Not implemented yet")
}

// Gets the x509.Certificate associated with this TPMv2Signer
func (tpmv2Signer *TPMv2Signer) Certificate() (*x509.Certificate, error) {
	return tpmv2Signer.cert, nil
}

// Gets the certificate chain associated with this TPMv2Signer
func (tpmv2Signer *TPMv2Signer) CertificateChain() (chain []*x509.Certificate, err error) {
	return tpmv2Signer.certChain, nil
}

/*
 * DER forbids storing a BOOLEAN as anything but 0x00 or 0xFF,
 * 0x01, and the Go asn1 parser cannot be relaxed. But both
 * OpenSSL ENGINEs which produce these keys have at least in
 * the past emitted 0x01 as the value, leading to an Unmarshal
 * failure with 'asn1: syntax error: invalid boolean'. So...
 */
func fixupEmptyAuth(tpmData *[]byte) {
	var pos int = 0

	// Skip the SEQUENCE tag and length
	if len(*tpmData) < 2 || (*tpmData)[0] != 0x30 {
		return
	}

	// Don't care what the SEQUENCE length is, just skip it
	pos = 1
	lenByte := (*tpmData)[pos]
	if lenByte < 0x80 {
		pos = pos + 1
	} else if lenByte < 0x85 {
		pos = pos + 1 + int(lenByte) - 0x80
	} else {
		return
	}

	if len(*tpmData) <= pos {
		return
	}

	// Use asn1.Unmarshal to eat the OID; we care about 'rest'
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal((*tpmData)[pos:], &oid)
	if err != nil || rest == nil || !oid.Equal(oidLoadableKey) || len(rest) < 5 {
		return
	}

	// If the OPTIONAL EXPLICIT BOOLEAN [0] exists, it'll be here
	pos = len(*tpmData) - len(rest)

	if (*tpmData)[pos] == 0xa0 && // Tag
		(*tpmData)[pos+1] == 0x03 && // length
		(*tpmData)[pos+2] == 0x01 &&
		(*tpmData)[pos+3] == 0x01 &&
		(*tpmData)[pos+4] == 0x01 {
		(*tpmData)[pos+4] = 0xff
	}
}

// Returns a TPMv2Signer, that can be used to sign a payload through a TPMv2-compatible
// cryptographic device
func GetTPMv2Signer(certificate *x509.Certificate, certificateChain []*x509.Certificate, keyPem *pem.Block) (signer Signer, signingAlgorithm string, err error) {

	var tpmData tpm2_TPMKey

	fixupEmptyAuth(&keyPem.Bytes)
	_, err = asn1.Unmarshal(keyPem.Bytes, &tpmData)
	if err != nil {
		return nil, "", err
	}

	if !tpmData.Oid.Equal(oidLoadableKey) {
		return nil, "", errors.New("Invalid OID for TPMv2 key:" + tpmData.Oid.String())
	}

	if tpmData.Policy != nil || tpmData.AuthPolicy != nil {
		return nil, "", errors.New("TPMv2 policy not implemented yet")
	}
	if tpmData.Secret != nil {
		return nil, "", errors.New("TPMv2 key has 'secret' field which should not be set")
	}

	if !handleIsPersistent(tpmData.Parent) &&
		tpmData.Parent != int(tpm2.HandleOwner) &&
		tpmData.Parent != int(tpm2.HandleNull) &&
		tpmData.Parent != int(tpm2.HandleEndorsement) &&
		tpmData.Parent != int(tpm2.HandlePlatform) {
		return nil, "", errors.New("Invalid parent for TPMv2 key")
	}
	if len(tpmData.Pubkey) < 2 ||
		len(tpmData.Pubkey)-2 != (int(tpmData.Pubkey[0])<<8)+int(tpmData.Pubkey[1]) {
		return nil, "", errors.New("Invalid length for TPMv2 PUBLIC blob")
	}

	public, err := tpm2.DecodePublic(tpmData.Pubkey[2:])
	if err != nil {
		return nil, "", err
	}

	switch public.Type {
	case tpm2.AlgRSA:
		signingAlgorithm = aws4_x509_rsa_sha256
	case tpm2.AlgECC:
		signingAlgorithm = aws4_x509_ecdsa_sha256
	default:
		return nil, "", errors.New("Unsupported TPMv2 key type")
	}

	if len(tpmData.Privkey) < 2 ||
		len(tpmData.Privkey)-2 != (int(tpmData.Privkey[0])<<8)+int(tpmData.Privkey[1]) {
		return nil, "", errors.New("Invalid length for TPMv2 PRIVATE blob")
	}

	return &TPMv2Signer{certificate, nil, tpmData, public, tpmData.Privkey[2:]}, signingAlgorithm, nil
}
