package aws_signing_helper

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"golang.org/x/crypto/pkcs12"
)

type SignerParams struct {
	OverriddenDate   time.Time
	RegionName       string
	ServiceName      string
	SigningAlgorithm string
}

type CertIdentifier struct {
	Subject      string
	Issuer       string
	SerialNumber *big.Int
}

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")
)

// Interface that all signers will have to implement
// (as a result, they will also implement crypto.Signer)
type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Certificate() (certificate *x509.Certificate, err error)
	CertificateChain() (certificateChain []*x509.Certificate, err error)
	Close()
}

// Container for certificate data returned to the SDK as JSON.
type CertificateData struct {
	// Type for the key contained in the certificate.
	// Passed back to the `sign-string` command
	KeyType string `json:"keyType"`
	// Certificate, as base64-encoded DER; used in the `x-amz-x509`
	// header in the API request.
	CertificateData string `json:"certificateData"`
	// Serial number of the certificate. Used in the credential
	// field of the Authorization header
	SerialNumber string `json:"serialNumber"`
	// Supported signing algorithms based on the KeyType
	Algorithms []string `json:"supportedAlgorithms"`
}

// Container that adheres to the format of credential_process output as specified by AWS.
type CredentialProcessOutput struct {
	// This field should be hard-coded to 1 for now.
	Version int `json:"Version"`
	// AWS Access Key ID
	AccessKeyId string `json:"AccessKeyId"`
	// AWS Secret Access Key
	SecretAccessKey string `json:"SecretAccessKey"`
	// AWS Session Token for temporary credentials
	SessionToken string `json:"SessionToken"`
	// ISO8601 timestamp for when the credentials expire
	Expiration string `json:"Expiration"`
}

type CertificateContainer struct {
	// Certificate data
	Cert *x509.Certificate
	// Certificate URI (only populated in the case that the certificate is a PKCS#11 object)
	Uri string
}

// Define constants used in signing
const (
	aws4_x509_rsa_sha256   = "AWS4-X509-RSA-SHA256"
	aws4_x509_ecdsa_sha256 = "AWS4-X509-ECDSA-SHA256"
	timeFormat             = "20060102T150405Z"
	shortTimeFormat        = "20060102"
	x_amz_date             = "X-Amz-Date"
	x_amz_x509             = "X-Amz-X509"
	x_amz_x509_chain       = "X-Amz-X509-Chain"
	x_amz_content_sha256   = "X-Amz-Content-Sha256"
	authorization          = "Authorization"
	host                   = "Host"
	emptyStringSHA256      = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
)

// Headers that aren't included in calculating the signature
var ignoredHeaderKeys = map[string]bool{
	"Authorization":   true,
	"User-Agent":      true,
	"X-Amzn-Trace-Id": true,
}

var Debug bool = false

// Find whether the current certificate matches the CertIdentifier
func certMatches(certIdentifier CertIdentifier, cert x509.Certificate) bool {
	if certIdentifier.Subject != "" && certIdentifier.Subject != cert.Subject.String() {
		return false
	}
	if certIdentifier.Issuer != "" && certIdentifier.Issuer != cert.Issuer.String() {
		return false
	}
	if certIdentifier.SerialNumber != nil && certIdentifier.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}

	return true
}

// Because of *course* we have to do this for ourselves.
//
// Create the DER-encoded SEQUENCE containing R and S:
//
//	Ecdsa-Sig-Value ::= SEQUENCE {
//	  r                   INTEGER,
//	  s                   INTEGER
//	}
//
// This is defined in RFC3279 §2.2.3 as well as SEC.1.
// I can't find anything which mandates DER but I've seen
// OpenSSL refusing to verify it with indeterminate length.
func encodeEcdsaSigValue(signature []byte) (out []byte, err error) {
	sigLen := len(signature) / 2

	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
		big.NewInt(0).SetBytes(signature[:sigLen]),
		big.NewInt(0).SetBytes(signature[sigLen:])})
}

// Gets the Signer based on the flags passed in by the user (from which the CredentialsOpts structure is derived)
func GetSigner(opts *CredentialsOpts) (signer Signer, signatureAlgorithm string, err error) {
	var (
		certificate      *x509.Certificate
		certificateChain []*x509.Certificate
		privateKey       crypto.PrivateKey
	)

	privateKeyId := opts.PrivateKeyId
	if privateKeyId == "" {
		if opts.CertificateId == "" {
			if Debug {
				log.Println("attempting to use CertStoreSigner")
			}
			return GetCertStoreSigner(opts.CertIdentifier)
		}
		privateKeyId = opts.CertificateId
	}

	if opts.CertificateId != "" && !strings.HasPrefix(opts.CertificateId, "pkcs11:") {
		certificateData, err := ReadCertificateData(opts.CertificateId)
		if err == nil {
			certificateDerData, err := base64.StdEncoding.DecodeString(certificateData.CertificateData)
			if err != nil {
				return nil, "", err
			}
			certificate, err = x509.ParseCertificate([]byte(certificateDerData))
			if err != nil {
				return nil, "", err
			}
		} else if opts.PrivateKeyId == "" {
			if Debug {
				log.Println("not a PEM certificate, so trying PKCS#12")
			}
			if opts.CertificateBundleId != "" {
				return nil, "", errors.New("can't specify certificate chain when" +
					" using PKCS#12 files; certificate bundle should be provided" +
					" within the PKCS#12 file")
			}
			// Not a PEM certificate? Try PKCS#12
			certificateChain, privateKey, err = ReadPKCS12Data(opts.CertificateId)
			if err != nil {
				return nil, "", err
			}
			if privateKey != nil {
				ecPrivateKeyPtr, isEcKey := privateKey.(*ecdsa.PrivateKey)
				if isEcKey {
					privateKey = *ecPrivateKeyPtr
				}

				rsaPrivateKeyPtr, isRsaKey := privateKey.(*rsa.PrivateKey)
				if isRsaKey {
					privateKey = *rsaPrivateKeyPtr
				}
			}
			return GetFileSystemSigner(privateKey, certificateChain[0], certificateChain)
		} else {
			return nil, "", err
		}
	}

	if opts.CertificateBundleId != "" {
		certificateChainPointers, err := ReadCertificateBundleData(opts.CertificateBundleId)
		if err != nil {
			return nil, "", err
		}
		for _, certificate := range certificateChainPointers {
			certificateChain = append(certificateChain, certificate)
		}
	}

	if strings.HasPrefix(privateKeyId, "pkcs11:") {
		if Debug {
			log.Println("attempting to use PKCS11Signer")
		}
		if certificate != nil {
			opts.CertificateId = ""
		}
		return GetPKCS11Signer(opts.LibPkcs11, certificate, certificateChain, opts.PrivateKeyId, opts.CertificateId, opts.ReusePin)
	} else {
		privateKey, err = ReadPrivateKeyData(privateKeyId)
		if err != nil {
			return nil, "", err
		}

		if Debug {
			log.Println("attempting to use FileSystemSigner")
		}
		return GetFileSystemSigner(privateKey, certificate, certificateChain)
	}
}

// Obtain the date-time, formatted as specified by SigV4
func (signerParams *SignerParams) GetFormattedSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(timeFormat)
}

// Obtain the short date-time, formatted as specified by SigV4
func (signerParams *SignerParams) GetFormattedShortSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(shortTimeFormat)
}

// Obtain the scope as part of the SigV4-X509 signature
func (signerParams *SignerParams) GetScope() string {
	var scopeStringBuilder strings.Builder
	scopeStringBuilder.WriteString(signerParams.GetFormattedShortSigningDateTime())
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.RegionName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.ServiceName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString("aws4_request")
	return scopeStringBuilder.String()
}

// Convert certificate to string, so that it can be present in the HTTP request header
func certificateToString(certificate *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

// Convert certificate chain to string, so that it can be pressent in the HTTP request header
func certificateChainToString(certificateChain []*x509.Certificate) string {
	var x509ChainString strings.Builder
	for i, certificate := range certificateChain {
		x509ChainString.WriteString(certificateToString(certificate))
		if i != len(certificateChain)-1 {
			x509ChainString.WriteString(",")
		}
	}
	return x509ChainString.String()
}

func CreateRequestSignFunction(signer crypto.Signer, signingAlgorithm string, certificate *x509.Certificate, certificateChain []*x509.Certificate) func(*request.Request) {
	return func(req *request.Request) {
		region := req.ClientInfo.SigningRegion
		if region == "" {
			region = aws.StringValue(req.Config.Region)
		}

		name := req.ClientInfo.SigningName
		if name == "" {
			name = req.ClientInfo.ServiceName
		}

		signerParams := SignerParams{time.Now(), region, name, signingAlgorithm}

		// Set headers that are necessary for signing
		req.HTTPRequest.Header.Set(host, req.HTTPRequest.URL.Host)
		req.HTTPRequest.Header.Set(x_amz_date, signerParams.GetFormattedSigningDateTime())
		req.HTTPRequest.Header.Set(x_amz_x509, certificateToString(certificate))
		if certificateChain != nil {
			req.HTTPRequest.Header.Set(x_amz_x509_chain, certificateChainToString(certificateChain))
		}

		contentSha256 := calculateContentHash(req.HTTPRequest, req.Body)
		if req.HTTPRequest.Header.Get(x_amz_content_sha256) == "required" {
			req.HTTPRequest.Header.Set(x_amz_content_sha256, contentSha256)
		}

		canonicalRequest, signedHeadersString := createCanonicalRequest(req.HTTPRequest, req.Body, contentSha256)

		stringToSign := CreateStringToSign(canonicalRequest, signerParams)
		signatureBytes, err := signer.Sign(rand.Reader, []byte(stringToSign), crypto.SHA256)
		if err != nil {
			log.Println(err.Error())
			os.Exit(1)
		}
		signature := hex.EncodeToString(signatureBytes)

		req.HTTPRequest.Header.Set(authorization, BuildAuthorizationHeader(req.HTTPRequest, req.Body, signedHeadersString, signature, certificate, signerParams))
		req.SignedHeaderVals = req.HTTPRequest.Header
	}
}

// Find the SHA256 hash of the provided request body as a io.ReadSeeker
func makeSha256Reader(reader io.ReadSeeker) []byte {
	hash := sha256.New()
	start, _ := reader.Seek(0, 1)
	defer reader.Seek(start, 0)

	io.Copy(hash, reader)
	return hash.Sum(nil)
}

// Calculate the hash of the request body
func calculateContentHash(r *http.Request, body io.ReadSeeker) string {
	hash := r.Header.Get(x_amz_content_sha256)

	if hash == "" {
		if body == nil {
			hash = emptyStringSHA256
		} else {
			hash = hex.EncodeToString(makeSha256Reader(body))
		}
	}

	return hash
}

// Create the canonical query string.
func createCanonicalQueryString(r *http.Request, body io.ReadSeeker) string {
	rawQuery := strings.Replace(r.URL.Query().Encode(), "+", "%20", -1)
	return rawQuery
}

// Create the canonical header string.
func createCanonicalHeaderString(r *http.Request) (string, string) {
	var headers []string
	signedHeaderVals := make(http.Header)
	for k, v := range r.Header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if ignoredHeaderKeys[canonicalKey] {
			continue
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			signedHeaderVals[lowerCaseKey] = append(signedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		headerValues[i] = k + ":" + strings.Join(signedHeaderVals[k], ",")
	}
	stripExcessSpaces(headerValues)
	return strings.Join(headerValues, "\n"), strings.Join(headers, ";")
}

const doubleSpace = "  "

// stripExcessSpaces will rewrite the passed in slice's string values to not
// contain muliple side-by-side spaces.
func stripExcessSpaces(vals []string) {
	var j, k, l, m, spaces int
	for i, str := range vals {
		// Trim trailing spaces
		for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
		}

		// Trim leading spaces
		for k = 0; k < j && str[k] == ' '; k++ {
		}
		str = str[k : j+1]

		// Strip multiple spaces.
		j = strings.Index(str, doubleSpace)
		if j < 0 {
			vals[i] = str
			continue
		}

		buf := []byte(str)
		for k, m, l = j, j, len(buf); k < l; k++ {
			if buf[k] == ' ' {
				if spaces == 0 {
					// First space.
					buf[m] = buf[k]
					m++
				}
				spaces++
			} else {
				// End of multiple spaces.
				spaces = 0
				buf[m] = buf[k]
				m++
			}
		}

		vals[i] = string(buf[:m])
	}
}

// Create the canonical request.
func createCanonicalRequest(r *http.Request, body io.ReadSeeker, contentSha256 string) (string, string) {
	var canonicalRequestStrBuilder strings.Builder
	canonicalHeaderString, signedHeadersString := createCanonicalHeaderString(r)
	canonicalRequestStrBuilder.WriteString("POST")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString("/sessions")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(createCanonicalQueryString(r, body))
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(canonicalHeaderString)
	canonicalRequestStrBuilder.WriteString("\n\n")
	canonicalRequestStrBuilder.WriteString(signedHeadersString)
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(contentSha256)
	canonicalRequestString := canonicalRequestStrBuilder.String()
	canonicalRequestStringHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	return hex.EncodeToString(canonicalRequestStringHashBytes[:]), signedHeadersString
}

// Create the string to sign.
func CreateStringToSign(canonicalRequest string, signerParams SignerParams) string {
	var stringToSignStrBuilder strings.Builder
	stringToSignStrBuilder.WriteString(signerParams.SigningAlgorithm)
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.GetFormattedSigningDateTime())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.GetScope())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(canonicalRequest)
	stringToSign := stringToSignStrBuilder.String()
	return stringToSign
}

// Builds the complete authorization header
func BuildAuthorizationHeader(request *http.Request, body io.ReadSeeker, signedHeadersString string, signature string, certificate *x509.Certificate, signerParams SignerParams) string {
	signingCredentials := certificate.SerialNumber.String() + "/" + signerParams.GetScope()
	credential := "Credential=" + signingCredentials
	signerHeaders := "SignedHeaders=" + signedHeadersString
	signatureHeader := "Signature=" + signature

	var authHeaderStringBuilder strings.Builder
	authHeaderStringBuilder.WriteString(signerParams.SigningAlgorithm)
	authHeaderStringBuilder.WriteString(" ")
	authHeaderStringBuilder.WriteString(credential)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signerHeaders)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signatureHeader)
	authHeaderString := authHeaderStringBuilder.String()
	return authHeaderString
}

func encodeDer(der []byte) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(der)
	encoder.Close()
	return buf.String(), nil
}

func parseDERFromPEM(pemDataId string, blockType string) (*pem.Block, error) {
	bytes, err := os.ReadFile(pemDataId)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var block *pem.Block
	for len(bytes) > 0 {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			return nil, errors.New("unable to parse PEM data")
		}
		if block.Type == blockType {
			return block, nil
		}
	}
	return nil, errors.New("requested block type could not be found")
}

// Reads certificate bundle data from a file, whose path is provided
func ReadCertificateBundleData(certificateBundleId string) ([]*x509.Certificate, error) {
	bytes, err := os.ReadFile(certificateBundleId)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var derBytes []byte
	var block *pem.Block
	for len(bytes) > 0 {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate chain")
		}
		blockBytes := block.Bytes
		derBytes = append(derBytes, blockBytes...)
	}

	return x509.ParseCertificates(derBytes)
}

func readECPrivateKey(privateKeyId string) (ecdsa.PrivateKey, error) {
	block, err := parseDERFromPEM(privateKeyId, "EC PRIVATE KEY")
	if err != nil {
		return ecdsa.PrivateKey{}, errors.New("could not parse PEM data")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return ecdsa.PrivateKey{}, errors.New("could not parse private key")
	}

	return *privateKey, nil
}

func readRSAPrivateKey(privateKeyId string) (rsa.PrivateKey, error) {
	block, err := parseDERFromPEM(privateKeyId, "RSA PRIVATE KEY")
	if err != nil {
		return rsa.PrivateKey{}, errors.New("could not parse PEM data")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return rsa.PrivateKey{}, errors.New("could not parse private key")
	}

	return *privateKey, nil
}

func readPKCS8PrivateKey(privateKeyId string) (crypto.PrivateKey, error) {
	block, err := parseDERFromPEM(privateKeyId, "PRIVATE KEY")
	if err != nil {
		return nil, errors.New("could not parse PEM data")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("could not parse private key")
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		return *rsaPrivateKey, nil
	}

	ecPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if ok {
		return *ecPrivateKey, nil
	}

	return nil, errors.New("could not parse PKCS#8 private key")
}

// Reads and parses a PKCS#12 file (which should contain an end-entity
// certificate, (optional) certificate chain, and the key associated with the
// end-entity certificate). The end-entity certificate will be the first
// certificate in the returned chain. This method assumes that there is
// exactly one certificate that doesn't issue any others within the container
// and treats that as the end-entity certificate. Also, the order of the other
// certificates in the chain aren't guaranteed (it's also not guaranteed that
// those certificates form a chain with the end-entity certificat either).
func ReadPKCS12Data(certificateId string) (certChain []*x509.Certificate, privateKey crypto.PrivateKey, err error) {
	var (
		bytes               []byte
		pemBlocks           []*pem.Block
		parsedCerts         []*x509.Certificate
		certMap             map[string]*x509.Certificate
		endEntityFoundIndex int
	)

	bytes, err = os.ReadFile(certificateId)
	if err != nil {
		return nil, nil, nil
	}

	pemBlocks, err = pkcs12.ToPEM(bytes, "")
	if err != nil {
		return nil, "", err
	}

	for _, block := range pemBlocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			parsedCerts = append(parsedCerts, cert)
			continue
		}
		privateKeyTmp, err := ReadPrivateKeyDataFromPEMBlock(block)
		if err == nil {
			privateKey = privateKeyTmp
			continue
		}
		// If neither a certificate nor a private key could be parsed from the
		// Block, ignore it and continue.
		if Debug {
			log.Println("unable to parse PEM block in PKCS#12 file - skipping")
		}
	}

	certMap = make(map[string]*x509.Certificate)
	for _, cert := range parsedCerts {
		// pkix.Name.String() roughly following the RFC 2253 Distinguished Names
		// syntax, so we assume that it's canonical.
		issuer := cert.Issuer.String()
		certMap[issuer] = cert
	}

	endEntityFoundIndex = -1
	for i, cert := range parsedCerts {
		subject := cert.Subject.String()
		if _, ok := certMap[subject]; !ok {
			certChain = append(certChain, cert)
			endEntityFoundIndex = i
			break
		}
	}
	if endEntityFoundIndex == -1 {
		return nil, "", errors.New("no end-entity certificate found in PKCS#12 file")
	}

	for i, cert := range parsedCerts {
		if i != endEntityFoundIndex {
			certChain = append(certChain, cert)
		}
	}

	return certChain, privateKey, nil
}

// Load the private key referenced by `privateKeyId`.
func ReadPrivateKeyData(privateKeyId string) (crypto.PrivateKey, error) {
	if key, err := readPKCS8PrivateKey(privateKeyId); err == nil {
		return key, nil
	}

	if key, err := readECPrivateKey(privateKeyId); err == nil {
		return key, nil
	}

	if key, err := readRSAPrivateKey(privateKeyId); err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse private key")
}

// Reads private key data from a *pem.Block.
func ReadPrivateKeyDataFromPEMBlock(block *pem.Block) (key crypto.PrivateKey, err error) {
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse private key")
}

// Load the certificate referenced by `certificateId` and extract
// details required by the SDK to construct the StringToSign.
func ReadCertificateData(certificateId string) (CertificateData, error) {
	block, err := parseDERFromPEM(certificateId, "CERTIFICATE")
	if err != nil {
		return CertificateData{}, errors.New("could not parse PEM data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("could not parse certificate", err)
		return CertificateData{}, errors.New("could not parse certificate")
	}

	//extract serial number
	serialNumber := cert.SerialNumber.String()

	//encode certificate
	encodedDer, _ := encodeDer(block.Bytes)

	//extract key type
	var keyType string
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "RSA"
	case x509.ECDSA:
		keyType = "EC"
	default:
		keyType = ""
	}

	supportedAlgorithms := []string{
		fmt.Sprintf("%sSHA256", keyType),
		fmt.Sprintf("%sSHA384", keyType),
		fmt.Sprintf("%sSHA512", keyType),
	}

	//return struct
	return CertificateData{keyType, encodedDer, serialNumber, supportedAlgorithms}, nil
}
