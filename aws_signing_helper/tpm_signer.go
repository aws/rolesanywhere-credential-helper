package aws_signing_helper

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	tpm2 "github.com/google/go-tpm/tpm2"
	tpmutil "github.com/google/go-tpm/tpmutil"
)

type tpm2_TPMPolicy struct {
	CommandCode   int    `asn1:"explicit,tag:0"`
	CommandPolicy []byte `asn1:"explicit,tag:1"`
}

type tpm2_TPMAuthPolicy struct {
	Name   string           `asn1:"utf8,optional,explicit,tag:0"`
	Policy []tpm2_TPMPolicy `asn1:"explicit,tag:1"`
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
var TPM_RC_AUTH_FAIL = "0x22"

type TPMv2Signer struct {
	cert      *x509.Certificate
	certChain []*x509.Certificate
	tpmData   tpm2_TPMKey
	public    tpm2.Public
	private   []byte
	password  string
	emptyAuth bool
	handle    tpmutil.Handle
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

type GetTPMv2SignerOpts struct {
	certificate      *x509.Certificate
	certificateChain []*x509.Certificate
	keyPem           *pem.Block
	password         string
	emptyAuth        bool
	handle           string
}
