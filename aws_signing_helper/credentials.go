package aws_signing_helper

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
)

type CredentialsOpts struct {
	PrivateKeyId        string
	CertificateId       string
	CertificateBundleId string
	CertIdentifier      CertIdentifier
	RoleArn             string
	ProfileArnStr       string
	TrustAnchorArnStr   string
	SessionDuration     int
	Region              string
	Endpoint            string
	NoVerifySSL         bool
	WithProxy           bool
	Debug               bool
	Version             string
	PinPkcs11			string
	LibPkcs11			string
	CheckPkcs11			bool
}

// Function to create session and generate credentials
func GenerateCredentials(opts *CredentialsOpts) (CredentialProcessOutput, error) {
	// assign values to region and endpoint if they haven't already been assigned
	trustAnchorArn, err := arn.Parse(opts.TrustAnchorArnStr)
	if err != nil {
		return CredentialProcessOutput{}, err
	}
	profileArn, err := arn.Parse(opts.ProfileArnStr)
	if err != nil {
		return CredentialProcessOutput{}, err
	}

	if trustAnchorArn.Region != profileArn.Region {
		return CredentialProcessOutput{}, err
	}

	if opts.Region == "" {
		opts.Region = trustAnchorArn.Region
	}

	if opts.CheckPkcs11 {
		//pkcs11GetInfo()
	}

	var signer Signer
	var signingAlgorithm string
	if opts.PrivateKeyId != "" {
		privateKey, err := ReadPrivateKeyData(opts.PrivateKeyId)
		if err != nil {
			return CredentialProcessOutput{}, err
		}
		signer, signingAlgorithm, err = GetFileSystemSigner(privateKey, opts.CertificateId, opts.CertificateBundleId)
		if err != nil {
			return CredentialProcessOutput{}, errors.New("unable to create request signer")
		}
	} else if opts.PinPkcs11 != "" && opts.LibPkcs11 != "" {
		signer, signingAlgorithm, err = GetPKCS11Signer(opts.CertIdentifier, opts.LibPkcs11, opts.PinPkcs11)
		if err != nil {
			return CredentialProcessOutput{}, errors.New("unable to create request signer")
		}
	} else {
		signer, signingAlgorithm, err = GetCertStoreSigner(opts.CertIdentifier)
		if err != nil {
			log.Println(err)
			return CredentialProcessOutput{}, errors.New("unable to create request signer")
		}
	}

	mySession := session.Must(session.NewSession())

	var logLevel aws.LogLevelType
	if opts.Debug {
		logLevel = aws.LogDebug
	} else {
		logLevel = aws.LogOff
	}

	var tr *http.Transport
	if opts.WithProxy {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.NoVerifySSL},
			Proxy:           http.ProxyFromEnvironment,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.NoVerifySSL},
		}
	}
	client := &http.Client{Transport: tr}
	config := aws.NewConfig().WithRegion(opts.Region).WithHTTPClient(client).WithLogLevel(logLevel)
	if opts.Endpoint != "" {
		config.WithEndpoint(opts.Endpoint)
	}
	rolesAnywhereClient := rolesanywhere.New(mySession, config)
	rolesAnywhereClient.Handlers.Build.RemoveByName("core.SDKVersionUserAgentHandler")
	rolesAnywhereClient.Handlers.Build.PushBackNamed(request.NamedHandler{Name: "v4x509.CredHelperUserAgentHandler", Fn: request.MakeAddToUserAgentHandler("CredHelper", opts.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)})
	rolesAnywhereClient.Handlers.Sign.Clear()
	certificate, err := signer.Certificate()
	if err != nil {
		return CredentialProcessOutput{}, errors.New("unable to find certificate")
	}
	certificateChain, err := signer.CertificateChain()
	if err != nil {
		return CredentialProcessOutput{}, errors.New("unable to find certificate chain")
	}
	rolesAnywhereClient.Handlers.Sign.PushBackNamed(request.NamedHandler{Name: "v4x509.SignRequestHandler", Fn: CreateRequestSignFunction(signer, signingAlgorithm, certificate, certificateChain)})

	certificateStr := base64.StdEncoding.EncodeToString(certificate.Raw)
	durationSeconds := int64(opts.SessionDuration)
	createSessionRequest := rolesanywhere.CreateSessionInput{
		Cert:               &certificateStr,
		ProfileArn:         &opts.ProfileArnStr,
		TrustAnchorArn:     &opts.TrustAnchorArnStr,
		DurationSeconds:    &(durationSeconds),
		InstanceProperties: nil,
		RoleArn:            &opts.RoleArn,
		SessionName:        nil,
	}
	output, err := rolesAnywhereClient.CreateSession(&createSessionRequest)
	if err != nil {
		return CredentialProcessOutput{}, err
	}

	if len(output.CredentialSet) == 0 {
		msg := "unable to obtain temporary security credentials from CreateSession"
		return CredentialProcessOutput{}, errors.New(msg)
	}
	credentials := output.CredentialSet[0].Credentials
	credentialProcessOutput := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     *credentials.AccessKeyId,
		SecretAccessKey: *credentials.SecretAccessKey,
		SessionToken:    *credentials.SessionToken,
		Expiration:      *credentials.Expiration,
	}
	return credentialProcessOutput, nil
}
