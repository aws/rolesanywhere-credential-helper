package aws_signing_helper

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const UpdateRefreshTime = time.Minute * time.Duration(5)

// Structure to contain a temporary credential
type TemporaryCredential struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// Assume the `credential` file is located in the default path: `~/.aws/credentials`
func GetOrCreateCredentialsFile() (*os.File, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("unable to locate the home directory")
		return nil, err
	}

	awsCredentialsPath := filepath.Join(homeDir, ".aws", "credentials")
	if err = os.MkdirAll(filepath.Dir(awsCredentialsPath), 0700); err != nil { // nosemgrep
		log.Println("unable to create credentials file")
		return nil, err
	}

	return os.OpenFile(awsCredentialsPath, os.O_RDONLY|os.O_CREATE, 0600)
}

// Function to replace the current AWS Credential file with `tempFile`
func Replace(currentCredential *os.File, tmpFile *os.File) error {
	err := os.Rename(tmpFile.Name(), currentCredential.Name())

	// Manually copy&paste the content if `os.Rename()` fails
	if err != nil {
		in, err := os.Open(tmpFile.Name())
		if err != nil {
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(currentCredential.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}

	return err
}

// Function to write existing credentials and newly-created credentials to a destination file
func WriteTo(profileName string, destFile *os.File, writeLines []string, cred *TemporaryCredential) {
	var profileExist = false
	var profileSection = "[" + profileName + "]"
	// A variable that checks whether or not required fields are written to the destination file
	newCredVisit := map[string]bool{"aws_access_key_id": false, "aws_secret_access_key": false, "aws_session_token": false}
	accessKey := "aws_access_key_id = " + cred.AccessKeyId + "\n"
	secretKey := "aws_secret_access_key = " + cred.SecretAccessKey + "\n"
	sessionToken := "aws_session_token = " + cred.SessionToken + "\n"

	for i := 0; i < len(writeLines); i++ {
		if writeLines[i] == profileSection {
			j := i + 1
			destFile.WriteString(profileSection + "\n")
			for ; j < len(writeLines); j++ {
				// If the last line of the credentials file is reached
				// OR the next profile section is reached
				if j == len(writeLines)-1 || strings.HasPrefix(writeLines[j], "[") {
					if !newCredVisit["aws_access_key_id"] {
						destFile.WriteString(accessKey)
					}
					if !newCredVisit["aws_secret_access_key"] {
						destFile.WriteString(secretKey)
					}
					if !newCredVisit["aws_session_token"] {
						destFile.WriteString(sessionToken)

					}
					if j == len(writeLines)-1 {
						i = j
					} else {
						i = j - 1
					}
					profileExist = true
					break
				} else if strings.HasPrefix(writeLines[j], "aws_access_key_id") {
					// replace "aws_access_key_id"
					destFile.WriteString(accessKey)
					newCredVisit["aws_access_key_id"] = true
				} else if strings.HasPrefix(writeLines[j], "aws_secret_access_key") {
					// replace "aws_secret_access_key"
					destFile.WriteString(secretKey)
					newCredVisit["aws_secret_access_key"] = true
				} else if strings.HasPrefix(writeLines[j], "aws_session_token") {
					// replace "aws_session_token"
					destFile.WriteString(sessionToken)
					newCredVisit["aws_session_token"] = true
				} else {
					// write other keys
					destFile.WriteString(writeLines[j] + "\n")
				}
			}
		} else {
			destFile.WriteString(writeLines[i] + "\n")
		}

	}

	// if a chosen profile does not exist
	if !profileExist {
		writeCredential := profileSection + "\n" + accessKey + secretKey + sessionToken
		destFile.WriteString(writeCredential + "\n")
	}
}

// Function to check whether credentials are still valid
func ValidCred(cred TemporaryCredential) bool {
	// if credentials are not issued by Roles Anywhere
	if (cred == TemporaryCredential{}) {
		return false
	}
	// if credentials are going to expire in five minutes
	if time.Until(cred.Expiration) <= UpdateRefreshTime {
		return false
	}

	return true
}
