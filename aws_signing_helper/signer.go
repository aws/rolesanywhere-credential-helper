package aws_signing_helper

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
)

type SigningOpts struct {
	// Private key to use for the signing operation.
	PrivateKey crypto.PrivateKey
	// Digest to use in the signing operation. For example, SHA256
	Digest crypto.Hash
}

// Container for data that will be sent in a request to CreateSession.
type RequestOpts struct {
	// ARN of the Role to assume in the CreateSession call.
	RoleArn string
	// ARN of the Configuration to use in the CreateSession call.
	ConfigurationArn string
	// Certificate, as base64-encoded DER; used in the `x-amz-x509`
	// header in the API request.
	CertificateData string
	// Duration of the session that will be returned by CreateSession.
	DurationSeconds int
}

type RequestHeaderOpts struct {
	// Certificate, as base64-encoded DER; used in the `x-amz-x509`
	// header in the API request.
	CertificateData string
}

type RequestQueryStringOpts struct {
	// ARN of the Role to assume in the CreateSession call.
	RoleArn string
	// ARN of the Configuration to use in the CreateSession call.
	ConfigurationArn string
}

type SignerParams struct {
	OverriddenDate   time.Time
	RegionName       string
	ServiceName      string
	SigningAlgorithm string
}

// Container for data returned after performing a signing operation.
type SigningResult struct {
	// Signature encoded in hex.
	Signature string `json:"signature"`
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

type RolesAnywhereSigner struct {
	PrivateKey       crypto.PrivateKey
	Certificate      x509.Certificate
	CertificateChain []x509.Certificate
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
func certificateToString(certificate x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

// Convert certificate chain to string, so that it can be pressent in the HTTP request header
func certificateChainToString(certificateChain []x509.Certificate) string {
	var x509ChainString strings.Builder
	for i, certificate := range certificateChain {
		x509ChainString.WriteString(certificateToString(certificate))
		if i != len(certificateChain)-1 {
			x509ChainString.WriteString(",")
		}
	}
	return x509ChainString.String()
}

// Create a function that will sign requests, given the signing certificate, optional certificate chain, and the private key
func CreateSignFunction(privateKey crypto.PrivateKey, certificate x509.Certificate, certificateChain []x509.Certificate) func(*request.Request) {
	v4x509 := RolesAnywhereSigner{privateKey, certificate, certificateChain}
	return func(r *request.Request) {
		v4x509.SignWithCurrTime(r)
	}
}

// Sign the request using the current time
func (v4x509 RolesAnywhereSigner) SignWithCurrTime(req *request.Request) error {
	// Find the signing algorithm
	var signingAlgorithm string
	_, isRsaKey := v4x509.PrivateKey.(rsa.PrivateKey)
	if isRsaKey {
		signingAlgorithm = aws4_x509_rsa_sha256
	}
	_, isEcKey := v4x509.PrivateKey.(ecdsa.PrivateKey)
	if isEcKey {
		signingAlgorithm = aws4_x509_ecdsa_sha256
	}
	if signingAlgorithm == "" {
		log.Println("unsupported algorithm")
		return errors.New("unsupported algorithm")
	}

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
	req.HTTPRequest.Header.Set(x_amz_x509, certificateToString(v4x509.Certificate))
	if v4x509.CertificateChain != nil {
		req.HTTPRequest.Header.Set(x_amz_x509_chain, certificateChainToString(v4x509.CertificateChain))
	}

	contentSha256 := calculateContentHash(req.HTTPRequest, req.Body)
	if req.HTTPRequest.Header.Get(x_amz_content_sha256) == "required" {
		req.HTTPRequest.Header.Set(x_amz_content_sha256, contentSha256)
	}

	canonicalRequest, signedHeadersString := createCanonicalRequest(req.HTTPRequest, req.Body, contentSha256)

	stringToSign := CreateStringToSign(canonicalRequest, signerParams)

	signingResult, _ := Sign([]byte(stringToSign), SigningOpts{v4x509.PrivateKey, crypto.SHA256})

	req.HTTPRequest.Header.Set(authorization, BuildAuthorizationHeader(req.HTTPRequest, req.Body, signedHeadersString, signingResult.Signature, v4x509.Certificate, signerParams))
	req.SignedHeaderVals = req.HTTPRequest.Header
	return nil
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
func BuildAuthorizationHeader(request *http.Request, body io.ReadSeeker, signedHeadersString string, signature string, certificate x509.Certificate, signerParams SignerParams) string {
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

// Sign the provided payload with the specified options.
func Sign(payload []byte, opts SigningOpts) (SigningResult, error) {
	var hash []byte
	switch opts.Digest {
	case crypto.SHA256:
		sum := sha256.Sum256(payload)
		hash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(payload)
		hash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(payload)
		hash = sum[:]
	default:
		log.Println("unsupported digest")
		return SigningResult{}, errors.New("unsupported digest")
	}

	ecdsaPrivateKey, ok := opts.PrivateKey.(ecdsa.PrivateKey)
	if ok {
		sig, err := ecdsa.SignASN1(rand.Reader, &ecdsaPrivateKey, hash[:])
		if err == nil {
			return SigningResult{hex.EncodeToString(sig)}, nil
		}
	}

	rsaPrivateKey, ok := opts.PrivateKey.(rsa.PrivateKey)
	if ok {
		sig, err := rsa.SignPKCS1v15(rand.Reader, &rsaPrivateKey, opts.Digest, hash[:])
		if err == nil {
			return SigningResult{hex.EncodeToString(sig)}, nil
		}
	}

	log.Println("unsupported algorithm")
	return SigningResult{}, errors.New("unsupported algorithm")
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
			return nil, errors.New("unable to parse PEM data")
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

	return nil, errors.New("could not parse PKCS8 private key")
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
