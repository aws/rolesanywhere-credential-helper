package main

import (
	"bufio"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	helper "golang.a2z.com/CredHelper/aws_signing_helper"
)

// Common flags that must be contained in all flag sets
var (
	privateKeyId        string
	certificateId       string
	certificateBundleId string
	digestArg           string
	roleArnStr          string
	profileArnStr       string
	trustAnchorArnStr   string
	sessionDuration     int

	region      string
	endpoint    string
	noVerifySSL bool
	withProxy   bool
	debug       bool
	format      string
	profile     string
	once        bool

	port int

	credentialProcessCmd   = flag.NewFlagSet("credential-process", flag.ExitOnError)
	signStringCmd          = flag.NewFlagSet("sign-string", flag.ExitOnError)
	readCertificateDataCmd = flag.NewFlagSet("read-certificate-data", flag.ExitOnError)
	updateCmd              = flag.NewFlagSet("update", flag.ExitOnError)
	versionCmd             = flag.NewFlagSet("version", flag.ExitOnError)
	serveCmd               = flag.NewFlagSet("serve", flag.ExitOnError)
)

var Version string
var globalOptSet = map[string]bool{"--region": true, "--endpoint": true}

// Maps each command name to a flagset
var commands = map[string]*flag.FlagSet{
	credentialProcessCmd.Name():   credentialProcessCmd,
	signStringCmd.Name():          signStringCmd,
	readCertificateDataCmd.Name(): readCertificateDataCmd,
	updateCmd.Name():              updateCmd,
	versionCmd.Name():             versionCmd,
	serveCmd.Name():               serveCmd,
}

// Finds global parameters that can appear in any position
// Return a map that maps the name of global parameter to its value
//		and a list of remaining arguments
func findGlobalVar(argList []string) (map[string]string, []string) {
	globalVars := make(map[string]string)

	parseList := []string{}

	for i := 0; i < len(argList); i++ {

		if globalOptSet[argList[i]] {

			if !strings.HasPrefix(argList[i+1], "--") {
				globalVars[argList[i]] = argList[i+1]
				i = i + 1
			} else {
				log.Fatal("Invalid value for ", argList[i])
			}
		} else {
			parseList = append(parseList, argList[i])
		}
	}

	return globalVars, parseList
}

// Assigns different flags to different commands
func setupFlags() {
	for command, fs := range commands {
		// applicable to `sign-string`, `credential-process`, `update`, and `serve` operation
		if command != "read-certificate-data" {
			fs.StringVar(&privateKeyId, "private-key", "", "Path to private key file")
		}

		// applicable to `read-certificate-data`, `credential-process`, `update`, `serve` operation
		if command != "sign-string" {
			fs.StringVar(&certificateId, "certificate", "", "Path to certificate file")
		}

		// applicable to `credential-process` operation and possibly `update` operation and `serve` operation
		if command != "sign-string" && command != "read-certificate-data" {
			fs.StringVar(&roleArnStr, "role-arn", "", "Target role to assume")
			fs.StringVar(&profileArnStr, "profile-arn", "", "Profile to to pull policies from")
			fs.StringVar(&trustAnchorArnStr, "trust-anchor-arn", "", "Trust anchor to to use for authentication")
			fs.IntVar(&sessionDuration, "session-duration", 3600, "Duration, in seconds, for the resulting session")
			fs.StringVar(&region, "region", "", "Signing region")
			fs.StringVar(&endpoint, "endpoint", "", "Endpoint to retrieve session from")
			fs.StringVar(&certificateBundleId, "intermediates", "", "Path to intermediate certificate bundle")
			fs.BoolVar(&noVerifySSL, "no-verify-ssl", false, "To disable SSL verification")
			fs.BoolVar(&withProxy, "with-proxy", false, "To use credential-process with a proxy")
			fs.BoolVar(&debug, "debug", false, "To print debug output when SDK calls are made")
		}

		// applicable to `update` operation
		if command == "update" {
			fs.StringVar(&profile, "profile", "default", "The aws profile to use (default 'default')")
			fs.BoolVar(&once, "once", false, "Update the credentials once")
		}
	}

	// only applicable to `sign-string` operation
	commands["sign-string"].StringVar(&format, "format", "json", "Output format. One of json, text, and bin")
	commands["sign-string"].StringVar(&digestArg, "digest", "SHA256", "One of SHA256, SHA384 and SHA512")

	// only applicable to `serve` operation
	commands["serve"].IntVar(&port, "port", 9911, "The port used to run local server (default: 9911)")
}

func main() {
	setupFlags()

	// find and remove global variables
	globalVars, parseList := findGlobalVar(os.Args[1:])
	tmpRegion, regionDetected := globalVars["--region"]
	tmpEndpoint, endpointDetected := globalVars["--endpoint"]
	if len(parseList) == 0 || strings.HasPrefix(parseList[0], "--") {
		log.Println("No command provided")
		syscall.Exit(1)
	}

	command := parseList[0]
	commandFs, valid := commands[command]
	// if the command does not exist in the command list
	if !valid {
		log.Println("Unrecognized command")
		syscall.Exit(1)
	}

	commandFs.Parse(parseList[1:])

	// assign global variables if they have been detected
	if regionDetected {
		region = tmpRegion
	}
	if endpointDetected {
		endpoint = tmpEndpoint
	}
	credentialsOptions := helper.CredentialsOpts{
		PrivateKeyId:        privateKeyId,
		CertificateId:       certificateId,
		CertificateBundleId: certificateBundleId,
		RoleArn:             roleArnStr,
		ProfileArnStr:       profileArnStr,
		TrustAnchorArnStr:   trustAnchorArnStr,
		SessionDuration:     sessionDuration,
		Region:              region,
		Endpoint:            endpoint,
		NoVerifySSL:         noVerifySSL,
		WithProxy:           withProxy,
		Debug:               debug,
		Version:             Version,
	}

	switch command {
	case "credential-process":
		// First check whether required arguments are present
		if privateKeyId == "" || certificateId == "" || profileArnStr == "" ||
			trustAnchorArnStr == "" || roleArnStr == "" {
			msg := `Usage: aws_signing_helper credential-process
			--private-key <value> 
			--certificate <value> 
			--profile-arn <value> 
			--trust-anchor-arn <value>
			--role-arn <value> 
			[--endpoint <value>] 
			[--region <value>] 
			[--session-duration <value>]
			[--with-proxy]
			[--no-verify-ssl]
			[--debug]
			[--intermediates <value>]`
			log.Println(msg)
			syscall.Exit(1)
		}
		credentialProcessOutput, err := helper.GenerateCredentials(&credentialsOptions)
		if err != nil {
			log.Println(err)
			syscall.Exit(1)
		}
		buf, _ := json.Marshal(credentialProcessOutput)
		fmt.Print(string(buf[:]))
	case "sign-string":
		stringToSign, _ := ioutil.ReadAll(bufio.NewReader(os.Stdin))
		privateKey, _ := helper.ReadPrivateKeyData(privateKeyId)
		var digest crypto.Hash
		switch strings.ToUpper(digestArg) {
		case "SHA256":
			digest = crypto.SHA256
		case "SHA384":
			digest = crypto.SHA384
		case "SHA512":
			digest = crypto.SHA512
		default:
			digest = crypto.SHA256
		}
		signingResult, _ := helper.Sign(stringToSign, helper.SigningOpts{PrivateKey: privateKey, Digest: digest})
		switch strings.ToLower(format) {
		case "text":
			fmt.Print(signingResult.Signature)
		case "json":
			buf, _ := json.Marshal(signingResult)
			fmt.Print(string(buf[:]))
		case "bin":
			buf, _ := hex.DecodeString(signingResult.Signature)
			binary.Write(os.Stdout, binary.BigEndian, buf[:])
		default:
			fmt.Print(signingResult.Signature)
		}
	case "read-certificate-data":
		data, _ := helper.ReadCertificateData(certificateId)
		buf, _ := json.Marshal(data)
		fmt.Print(string(buf[:]))
	case "version":
		fmt.Println(Version)
	case "update":
		if privateKeyId == "" || certificateId == "" ||
			profileArnStr == "" || trustAnchorArnStr == "" || roleArnStr == "" {
			msg := `Usage: aws_signing_helper update
			--private-key <value> 
			--certificate <value> 
			--profile-arn <value> 
			--trust-anchor-arn <value>
			--role-arn <value> 
			[--endpoint <value>] 
			[--region <value>]
			[--session-duration <value>]
			[--with-proxy]
			[--no-verify-ssl]
			[--intermediates <value>]
			[--profile <value>]
			[--once]`
			log.Println(msg)
			syscall.Exit(1)
		}
		helper.Update(credentialsOptions, profile, once)
	case "serve":
		// First check whether required arguments are present
		if privateKeyId == "" || certificateId == "" || profileArnStr == "" ||
			trustAnchorArnStr == "" || roleArnStr == "" {
			msg := `Usage: aws_signing_helper serve
			--private-key <value> 
			--certificate <value> 
			--profile-arn <value> 
			--trust-anchor-arn <value>
			--role-arn <value> 
			[--endpoint <value>] 
			[--region <value>] 
			[--session-duration <value>]
			[--with-proxy]
			[--no-verify-ssl]
			[--debug]
			[--intermediates <value>]
			[--port <value>]`
			log.Println(msg)
			syscall.Exit(1)
		}

		var refreshableCred = helper.RefreshableCred{}

		credentialProcessOutput, _ := helper.GenerateCredentials(&credentialsOptions)
		refreshableCred.AccessKeyId = credentialProcessOutput.AccessKeyId
		refreshableCred.SecretAccessKey = credentialProcessOutput.SecretAccessKey
		refreshableCred.Token = credentialProcessOutput.SessionToken
		refreshableCred.Expiration, _ = time.Parse(time.RFC3339, credentialProcessOutput.Expiration)
		endpoint := &helper.Endpoint{PortNum: port, TmpCred: refreshableCred}
		endpoint.Server = &http.Server{}
		http.HandleFunc("/", helper.AllIssuesHandlers(&endpoint.TmpCred, &credentialsOptions))
		// start the credentials endpoint
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", helper.Address, endpoint.PortNum))
		if err != nil {
			log.Println("failed to create listener")
			syscall.Exit(1)
		}
		endpoint.PortNum = listener.Addr().(*net.TCPAddr).Port
		log.Println("Local server started on port:", endpoint.PortNum)
		log.Println("Make it available to the sdk by running:")
		log.Printf("export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:%d", endpoint.PortNum)
		if err := endpoint.Server.Serve(listener); err != nil {
			log.Println("Httpserver: ListenAndServe() error")
			syscall.Exit(1)
		}
	case "":
		log.Println("No command provided")
		syscall.Exit(1)
	default:
		log.Fatalf("Unrecognized command %s", command)
	}
}
