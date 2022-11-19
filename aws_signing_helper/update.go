package aws_signing_helper

import (
	"bufio"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const UpdateRefreshTime = time.Minute * time.Duration(5)
const AwsSharedCredentialsFileEnvVarName = "AWS_SHARED_CREDENTIALS_FILE"

// Structure to contain a temporary credential
type TemporaryCredential struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// Updates credentials in the credentials file for the specified profile
func Update(credentialsOptions CredentialsOpts, profile string, once bool) {
	var refreshableCred = TemporaryCredential{}
	var nextRefreshTime time.Time
	for {
		credentialProcessOutput, err := GenerateCredentials(&credentialsOptions)
		if err != nil {
			log.Fatal(err)
		}

		// Assign credential values
		refreshableCred.AccessKeyId = credentialProcessOutput.AccessKeyId
		refreshableCred.SecretAccessKey = credentialProcessOutput.SecretAccessKey
		refreshableCred.SessionToken = credentialProcessOutput.SessionToken // nosemgrep
		refreshableCred.Expiration, _ = time.Parse(time.RFC3339, credentialProcessOutput.Expiration)
		if (refreshableCred == TemporaryCredential{}) {
			log.Println("no credentials created")
			syscall.Exit(1)
		}

		// Get credentials file contents
		lines, err := GetCredentialsFileContents()
		if err != nil {
			log.Println("unable to get credentials file contents")
			syscall.Exit(1)
		}

		// Write to credentials file
		err = WriteTo(profile, lines, &refreshableCred)
		if err != nil {
			log.Println("unable to write to AWS credentials file")
			syscall.Exit(1)
		}

		if once {
			break
		}
		nextRefreshTime = refreshableCred.Expiration.Add(-UpdateRefreshTime)
		log.Println("Credentials will be refreshed at", nextRefreshTime.String())
		time.Sleep(time.Until(nextRefreshTime))
	}
}

// Assume that the credentials file is located in the default path: `~/.aws/credentials`
func GetCredentialsFileContents() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("unable to locate the home directory")
		return nil, err
	}

	awsCredentialsPath := os.Getenv(AwsSharedCredentialsFileEnvVarName)
	if awsCredentialsPath == "" {
		awsCredentialsPath = filepath.Join(homeDir, ".aws", "credentials")
	}
	if err = os.MkdirAll(filepath.Dir(awsCredentialsPath), 0600); err != nil {
		log.Println("unable to create credentials file")
		return nil, err
	}

	readOnlyCredentialsFile, err := os.OpenFile(awsCredentialsPath, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Println("unable to get or create read-only AWS credentials file")
		syscall.Exit(1)
	}
	defer readOnlyCredentialsFile.Close()

	// Read in all profiles in the credentials file
	var lines []string
	scanner := bufio.NewScanner(readOnlyCredentialsFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

// Assume that the credentials file exists already and open it for write operations
func GetWriteOnlyCredentialsFile() (*os.File, error) {
	homeDir, _ := os.UserHomeDir()
	awsCredentialsPath := os.Getenv(AwsSharedCredentialsFileEnvVarName)
	if awsCredentialsPath == "" {
		awsCredentialsPath = filepath.Join(homeDir, ".aws", "credentials")
	}
	return os.OpenFile(awsCredentialsPath, os.O_WRONLY, 0200)
}

// Function to write existing credentials and newly-created credentials to a destination file
func WriteTo(profileName string, writeLines []string, cred *TemporaryCredential) error {
	destFile, err := GetWriteOnlyCredentialsFile()
	if err != nil {
		log.Println("unable to get write-only AWS credentials file")
		syscall.Exit(1)
	}
	defer destFile.Close()

	// Create buffered writer with a buffer of maximum size
	destFileWriter := bufio.NewWriterSize(destFile, math.MaxInt32)

	var profileExist = false
	var profileSection = "[" + profileName + "]"
	// A variable that checks whether or not required fields are written to the destination file
	newCredVisit := map[string]bool{"aws_access_key_id": false, "aws_secret_access_key": false, "aws_session_token": false}
	accessKey := "aws_access_key_id = " + cred.AccessKeyId + "\n"
	secretKey := "aws_secret_access_key = " + cred.SecretAccessKey + "\n"
	sessionToken := "aws_session_token = " + cred.SessionToken + "\n"

	for i := 0; i < len(writeLines); i++ {
		if !profileExist && writeLines[i] == profileSection {
			j := i + 1
			destFileWriter.WriteString(profileSection + "\n")
			for ; j < len(writeLines); j++ {
				// If the last line of the credentials file is reached
				// OR the next profile section is reached
				if j == len(writeLines)-1 || strings.HasPrefix(writeLines[j], "[") {
					if !newCredVisit["aws_access_key_id"] {
						_, err = destFileWriter.WriteString(accessKey)
					}
					if !newCredVisit["aws_secret_access_key"] {
						_, err = destFileWriter.WriteString(secretKey)
					}
					if !newCredVisit["aws_session_token"] {
						_, err = destFileWriter.WriteString(sessionToken)

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
					_, err = destFileWriter.WriteString(accessKey)
					newCredVisit["aws_access_key_id"] = true
				} else if strings.HasPrefix(writeLines[j], "aws_secret_access_key") {
					// replace "aws_secret_access_key"
					_, err = destFileWriter.WriteString(secretKey)
					newCredVisit["aws_secret_access_key"] = true
				} else if strings.HasPrefix(writeLines[j], "aws_session_token") {
					// replace "aws_session_token"
					_, err = destFileWriter.WriteString(sessionToken)
					newCredVisit["aws_session_token"] = true
				} else {
					// write other keys
					_, err = destFileWriter.WriteString(writeLines[j] + "\n")
				}
			}
		} else {
			_, err = destFileWriter.WriteString(writeLines[i] + "\n")
		}
	}

	// If the chosen profile does not exist
	if !profileExist {
		writeCredential := profileSection + "\n" + accessKey + secretKey + sessionToken
		_, err = destFileWriter.WriteString(writeCredential + "\n")
	}

	if err != nil {
		return err
	}

	// Flush the contents of the buffer
	destFileWriter.Flush()
	return nil
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
