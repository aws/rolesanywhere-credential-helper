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
	"os"
	"strings"
	"syscall"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
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

	profile string
	once    bool

	port int

	credentialProcessCmd   = flag.NewFlagSet("credential-process", flag.ExitOnError)
	signStringCmd          = flag.NewFlagSet("sign-string", flag.ExitOnError)
	readCertificateDataCmd = flag.NewFlagSet("read-certificate-data", flag.ExitOnError)
	updateCmd              = flag.NewFlagSet("update", flag.ExitOnError)
	serveCmd               = flag.NewFlagSet("serve", flag.ExitOnError)
	versionCmd             = flag.NewFlagSet("version", flag.ExitOnError)
)

var Version string
var globalOptSet = map[string]bool{"--region": true, "--endpoint": true}
var credentialCommands = map[string]struct{}{"credential-process": {}, "update": {}, "serve": {}}

// Maps each command name to a flagset
var commands = map[string]*flag.FlagSet{
	credentialProcessCmd.Name():   credentialProcessCmd,
	signStringCmd.Name():          signStringCmd,
	readCertificateDataCmd.Name(): readCertificateDataCmd,
	updateCmd.Name():              updateCmd,
	serveCmd.Name():               serveCmd,
	versionCmd.Name():             versionCmd,
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
				log.Println("Invalid value for ", argList[i])
				syscall.Exit(1)
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
		// Common flags for all credential-related commands
		if _, ok := credentialCommands[command]; ok {
			fs.StringVar(&certificateId, "certificate", "", "Path to certificate file")
			fs.StringVar(&privateKeyId, "private-key", "", "Path to private key file")
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

		if command == "read-certificate-data" {
			fs.StringVar(&certificateId, "certificate", "", "Path to certificate file")
		} else if command == "sign-string" {
			fs.StringVar(&privateKeyId, "private-key", "", "Path to private key file")
			fs.StringVar(&format, "format", "json", "Output format. One of json, text, and bin")
			fs.StringVar(&digestArg, "digest", "SHA256", "One of SHA256, SHA384 and SHA512")
		} else if command == "update" {
			fs.StringVar(&profile, "profile", "default", "The aws profile to use (default 'default')")
			fs.BoolVar(&once, "once", false, "Update the credentials once")
		} else if command == "serve" {
			fs.IntVar(&port, "port", helper.DefaultPort, "The port used to run local server (default: 9911)")
		}
	}
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
		helper.Serve(port, credentialsOptions)
	case "":
		log.Println("No command provided")
		syscall.Exit(1)
	default:
		log.Fatalf("Unrecognized command %s", command)
	}
}
