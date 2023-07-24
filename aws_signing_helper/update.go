package aws_signing_helper

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const UpdateRefreshTime = time.Minute * time.Duration(5)
const AwsSharedCredentialsFileEnvVarName = "AWS_SHARED_CREDENTIALS_FILE"
const BufferSize = 49152

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

	signer, signatureAlgorithm, err := GetSigner(&credentialsOptions)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer signer.Close()

	for {
		credentialProcessOutput, err := GenerateCredentials(&credentialsOptions, signer, signatureAlgorithm)
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
			os.Exit(1)
		}

		// Get credentials file contents
		lines, err := GetCredentialsFileContents()
		if err != nil {
			log.Println("unable to get credentials file contents")
			os.Exit(1)
		}

		// Write to credentials file
		err = WriteTo(profile, lines, &refreshableCred)
		if err != nil {
			log.Println("unable to write to AWS credentials file")
			os.Exit(1)
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
		os.Exit(1)
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
// that will overwrite the existing contents of the file
func GetWriteOnlyCredentialsFile() (*os.File, error) {
	homeDir, _ := os.UserHomeDir()
	awsCredentialsPath := os.Getenv(AwsSharedCredentialsFileEnvVarName)
	if awsCredentialsPath == "" {
		awsCredentialsPath = filepath.Join(homeDir, ".aws", "credentials")
	}
	return os.OpenFile(awsCredentialsPath, os.O_WRONLY|os.O_TRUNC, 0200)
}

// Function that will get the new conents of the credentials file after a
// refresh has been done
func GetNewCredentialsFileContents(profileName string, readLines []string, cred *TemporaryCredential) []string {
	var profileExist = false
	var profileSection = "[" + profileName + "]"
	// A variable that checks whether or not required fields are written to the destination file
	newCredVisit := map[string]bool{"aws_access_key_id": false, "aws_secret_access_key": false, "aws_session_token": false}
	accessKey := "aws_access_key_id = " + cred.AccessKeyId + "\n"
	secretKey := "aws_secret_access_key = " + cred.SecretAccessKey + "\n"
	sessionToken := "aws_session_token = " + cred.SessionToken + "\n"
	var writeLines = make([]string, 0)
	for readLinesIndex := 0; readLinesIndex < len(readLines); readLinesIndex++ {
		if !profileExist && readLines[readLinesIndex] == profileSection {
			writeLines = append(writeLines[:], profileSection+"\n")
			readLinesIndex += 1
			for ; readLinesIndex < len(readLines); readLinesIndex++ {
				// If the last line of the credentials file is reached
				// OR the next profile section is reached
				if readLinesIndex == len(readLines)-1 || strings.HasPrefix(readLines[readLinesIndex], "[") {
					if !newCredVisit["aws_access_key_id"] {
						writeLines = append(writeLines[:], accessKey)
					}
					if !newCredVisit["aws_secret_access_key"] {
						writeLines = append(writeLines[:], secretKey)
					}
					if !newCredVisit["aws_session_token"] {
						writeLines = append(writeLines[:], sessionToken)

					}
					if readLinesIndex != len(readLines)-1 {
						readLinesIndex -= 1
					}
					profileExist = true
					break
				} else if strings.HasPrefix(readLines[readLinesIndex], "aws_access_key_id") {
					// replace "aws_access_key_id"
					writeLines = append(writeLines[:], accessKey)
					newCredVisit["aws_access_key_id"] = true
				} else if strings.HasPrefix(readLines[readLinesIndex], "aws_secret_access_key") {
					// replace "aws_secret_access_key"
					writeLines = append(writeLines[:], secretKey)
					newCredVisit["aws_secret_access_key"] = true
				} else if strings.HasPrefix(readLines[readLinesIndex], "aws_session_token") {
					// replace "aws_session_token"
					writeLines = append(writeLines[:], sessionToken)
					newCredVisit["aws_session_token"] = true
				} else {
					// write other keys
					writeLines = append(writeLines[:], readLines[readLinesIndex]+"\n")
				}
			}
		} else {
			writeLines = append(writeLines[:], readLines[readLinesIndex]+"\n")
		}
	}

	// If the chosen profile does not exist
	if !profileExist {
		writeCredential := profileSection + "\n" + accessKey + secretKey + sessionToken
		writeLines = append(writeLines[:], writeCredential+"\n")
	}

	return writeLines
}

// Function to write existing credentials and newly-created credentials to a destination file
func WriteTo(profileName string, readLines []string, cred *TemporaryCredential) error {
	destFile, err := GetWriteOnlyCredentialsFile()
	if err != nil {
		log.Println("unable to get write-only AWS credentials file")
		os.Exit(1)
	}
	defer destFile.Close()

	// Create buffered writer
	destFileWriter := bufio.NewWriterSize(destFile, BufferSize)
	for _, line := range GetNewCredentialsFileContents(profileName, readLines, cred) {
		_, err := destFileWriter.WriteString(line)
		if err != nil {
			log.Println("unable to write to credentials file")
			os.Exit(1)
		}
	}

	// Flush the contents of the buffer
	destFileWriter.Flush()
	return nil
}
