package aws_signing_helper

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type CredentialsOpts struct {
	PrivateKeyId                 string
	CertificateId                string
	CertificateBundleId          string
	CertIdentifier               CertIdentifier
	UseLatestExpiringCertificate bool
	RoleArn                      string
	ProfileArnStr                string
	TrustAnchorArnStr            string
	SessionDuration              int
	Region                       string
	Endpoint                     string
	NoVerifySSL                  bool
	WithProxy                    bool
	Debug                        bool
	Version                      string
	LibPkcs11                    string
	ReusePin                     bool
	TpmKeyPassword               string
	NoTpmKeyPassword             bool
	ServerTTL                    int
	RoleSessionName              string
	Pkcs8Password                string
}

// Middleware to set a custom user agent header
func createCredHelperUserAgentMiddleware(userAgent string) middleware.BuildMiddleware {
	return middleware.BuildMiddlewareFunc("UserAgent", func(
		ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler,
	) (middleware.BuildOutput, middleware.Metadata, error) {
		if req, ok := input.Request.(*smithyhttp.Request); ok {
			req.Header.Set("User-Agent", userAgent)
		}
		return next.HandleBuild(ctx, input)
	})
}

// Function to create session and generate credentials
func GenerateCredentials(opts *CredentialsOpts, signer Signer, signatureAlgorithm string) (CredentialProcessOutput, error) {
	// Assign values to region and endpoint if they haven't already been assigned
	trustAnchorArn, err := arn.Parse(opts.TrustAnchorArnStr)
	if err != nil {
		return CredentialProcessOutput{}, fmt.Errorf("failed to parse trust anchor arn: '%w'", err)
	}
	profileArn, err := arn.Parse(opts.ProfileArnStr)
	if err != nil {
		return CredentialProcessOutput{}, fmt.Errorf("failed to parse profile arn: '%w'", err)
	}

	if trustAnchorArn.Region != profileArn.Region {
		return CredentialProcessOutput{}, errors.New("trust anchor and profile regions don't match")
	}

	if opts.Region == "" {
		opts.Region = trustAnchorArn.Region
	}

	var logMode aws.ClientLogMode = 0
	if Debug {
		logMode = aws.LogSigning | aws.LogRetries | aws.LogRequestWithBody | aws.LogResponseWithBody | aws.LogRequestEventMessage | aws.LogResponseEventMessage
	}

	// Custom HTTP client with proxy and TLS settings
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.NoVerifySSL}
		if opts.WithProxy {
			tr.Proxy = http.ProxyFromEnvironment
		}
	})
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(opts.Region), config.WithHTTPClient(httpClient), config.WithClientLogMode(logMode))
	if err != nil {
		return CredentialProcessOutput{}, err
	}

	// Override endpoint if specified
	if opts.Endpoint != "" {
		cfg.BaseEndpoint = aws.String(opts.Endpoint)
	}

	// Set a custom user agent
	userAgentStr := fmt.Sprintf("CredHelper/%s (%s; %s; %s)", opts.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		stack.Build.Remove("UserAgent")
		return stack.Build.Add(createCredHelperUserAgentMiddleware(userAgentStr), middleware.After)
	})

	// Add custom request signer, implementing SigV4-X509
	certificate, err := signer.Certificate()
	if err != nil {
		return CredentialProcessOutput{}, errors.New("unable to find certificate")
	}
	certificateChain, err := signer.CertificateChain()
	if err != nil {
		// If the chain couldn't be found, don't include it in the request
		if Debug {
			log.Println(err)
		}
	}
	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		// Remove middleware related to SigV4 signing
		stack.Finalize.Remove("Signing")
		stack.Finalize.Remove("setLegacyContextSigningOptions")
		stack.Finalize.Remove("GetIdentity")
		// Add middleware for SigV4-X509 signing
		stack.Finalize.Add(middleware.FinalizeMiddlewareFunc("Signing", CreateRequestSignFinalizeFunction(signer, opts.Region, signatureAlgorithm, certificate, certificateChain)), middleware.After)
		return nil
	})

	// Create the Roles Anywhere client using the above-constructed Config
	rolesAnywhereClient := rolesanywhere.NewFromConfig(cfg)

	certificateStr := base64.StdEncoding.EncodeToString(certificate.Raw)
	durationSeconds := int32(opts.SessionDuration)
	createSessionRequest := rolesanywhere.CreateSessionInput{
		Cert:               &certificateStr,
		ProfileArn:         &opts.ProfileArnStr,
		TrustAnchorArn:     &opts.TrustAnchorArnStr,
		DurationSeconds:    &(durationSeconds),
		InstanceProperties: nil,
		RoleArn:            &opts.RoleArn,
		SessionName:        nil,
	}
	if opts.RoleSessionName != "" {
		createSessionRequest.RoleSessionName = &opts.RoleSessionName
	}
	output, err := rolesAnywhereClient.CreateSession(ctx, &createSessionRequest)
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
