package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"

	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
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

var primaryParams = tpm2.Public{
	Type:       tpm2.AlgECC,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagNoDA | tpm2.FlagSensitiveDataOrigin,
	ECCParameters: &tpm2.ECCParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		Sign: &tpm2.SigScheme{
			Alg: tpm2.AlgNull,
		},
		CurveID: tpm2.CurveNISTP256,
		KDF: &tpm2.KDFScheme{
			Alg: tpm2.AlgNull,
		},
	},
}

// Returns the public key associated with this TPMv2Signer
func (tpmv2Signer *TPMv2Signer) Public() crypto.PublicKey {
	ret, _ := tpmv2Signer.public.Key()
	return ret
}

// Closes this TPMv2Signer
func (tpmv2Signer *TPMv2Signer) Close() {
}

func padPKCS1_15(input []byte, size uint) (output []byte, err error) {
	var PKCS1_PAD_OVERHEAD = 11

	if uint(len(input)+PKCS1_PAD_OVERHEAD) > size {
		return nil, errors.New("Digest too large for RSA signature")
	}

	padlen := size - uint(len(input))
	output = make([]byte, size)
	output[0] = 0x00
	output[1] = 0x01
	var i uint
	for i = 2; i < padlen-1; i++ {
		output[i] = 0xff
	}
	output[padlen-1] = 0x00
	copy(output[padlen:], input)
	return output, nil
}

// Implements the crypto.Signer interface and signs the passed in digest
func (tpmv2Signer *TPMv2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	rw, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	parentHandle := tpmutil.Handle(tpmv2Signer.tpmData.Parent)
	if !handleIsPersistent(tpmv2Signer.tpmData.Parent) {
		parentHandle, _, err = tpm2.CreatePrimary(rw, tpmutil.Handle(tpmv2Signer.tpmData.Parent), tpm2.PCRSelection{}, "", "", primaryParams)
		if err != nil {
			return nil, err
		}
		defer tpm2.FlushContext(rw, parentHandle)
	}

	keyHandle, _, err := tpm2.Load(rw, parentHandle, "", tpmv2Signer.tpmData.Pubkey[2:], tpmv2Signer.tpmData.Privkey[2:])
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, keyHandle)

	var algo tpm2.Algorithm
	var shadigest []byte
	var asn1Prefix []byte

	switch opts.HashFunc() {
	case crypto.SHA256:
		sha256digest := sha256.Sum256(digest)
		shadigest = sha256digest[:]
		algo = tpm2.AlgSHA256
		asn1Prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	case crypto.SHA384:
		sha384digest := sha512.Sum384(digest)
		shadigest = sha384digest[:]
		algo = tpm2.AlgSHA384
		asn1Prefix = []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
	case crypto.SHA512:
		sha512digest := sha512.Sum512(digest)
		shadigest = sha512digest[:]
		algo = tpm2.AlgSHA512
		asn1Prefix = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
	}

	if tpmv2Signer.public.Type == tpm2.AlgECC {

		// For an EC key we lie to the TPM about what the hash is.
		// It doesn't actually matter what the original digest was;
		// the algo we feed to the TPM is *purely* based on the
		// size of the curve itself. We truncate the actual digest,
		// or pad with zeroes, to the byte size of the key.
		pubKey, err := tpmv2Signer.public.Key()
		if err != nil {
			return nil, err
		}
		ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("Failed to obtain ecdsa.PublicKey")
		}
		bitSize := ecPubKey.Curve.Params().BitSize
		byteSize := (bitSize + 7) / 8
		if byteSize > sha512.Size {
			byteSize = sha512.Size
		}
		switch byteSize {
		case sha512.Size:
			algo = tpm2.AlgSHA512
		case sha512.Size384:
			algo = tpm2.AlgSHA384
		case sha512.Size256:
			algo = tpm2.AlgSHA256
		case sha1.Size:
			algo = tpm2.AlgSHA1
		default:
			return nil, errors.New("Unsupported curve")
		}

		if len(shadigest) > byteSize {
			shadigest = shadigest[:byteSize]
		}

		for len(shadigest) < byteSize {
			shadigest = append([]byte{0}, shadigest...)
		}

		sig, err := tpm2.Sign(rw, keyHandle, "", shadigest, nil,
			&tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: algo})
		if err != nil {
			return nil, err
		}
		signature, err = asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{sig.ECC.R, sig.ECC.S})
		if err != nil {
			return nil, err
		}
	} else {
		// Both OpenSSL ENGINEs perform a raw RSA Decrypt operation,
		// having done the ASN.1 encoding of the hash OID and the
		// actual, and the PKCS#1 v1.5 padding, in software. This
		// is because the TPM needs to *know* the digest in order
		// to use the Sign operation, and TPMs often don't support
		// many digest algorithms. The IBM/Bottomley engine even
		// creates keys without the Sign capability by default.
		padded, err := padPKCS1_15(append(asn1Prefix, shadigest...),
			uint(tpmv2Signer.public.RSAParameters.KeyBits/8))
		if err != nil {
			return nil, err
		}

		signature, err = tpm2.RSADecrypt(rw, keyHandle, "", padded, &tpm2.AsymScheme{Alg: tpm2.AlgNull}, "")
		if err != nil {
			return nil, err
		}
	}
	return signature, nil
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
