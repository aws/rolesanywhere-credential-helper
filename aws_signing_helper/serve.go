package aws_signing_helper

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const DefaultPort = 9911
const Address = "127.0.0.1"

var RefreshTime = time.Minute * time.Duration(5)

type RefreshableCred struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

type Endpoint struct {
	PortNum int
	Server  *http.Server
	TmpCred RefreshableCred
}

func AllIssuesHandlers(cred *RefreshableCred, opts *CredentialsOpts) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		var nextRefreshTime = cred.Expiration.Add(-RefreshTime)
		if time.Until(nextRefreshTime) < RefreshTime {
			credentialProcessOutput, _ := GenerateCredentials(opts)
			cred.AccessKeyId = credentialProcessOutput.AccessKeyId
			cred.SecretAccessKey = credentialProcessOutput.SecretAccessKey
			cred.Token = credentialProcessOutput.SessionToken
			cred.Expiration, _ = time.Parse(time.RFC3339, credentialProcessOutput.Expiration)
			err := json.NewEncoder(writer).Encode(cred)
			if err != nil {
				log.Fatal("Failed to encode")
			}
		} else {
			err := json.NewEncoder(writer).Encode(cred)
			if err != nil {
				log.Fatal("Failed to encode")
			}
		}
	}
}
