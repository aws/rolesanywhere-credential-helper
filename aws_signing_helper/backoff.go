package aws_signing_helper

import (
	"errors"
	"log"
	"math"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
)

const (
	// maxBackoff is the maximum backoff wait time for retries.
	maxBackoff = 30 * time.Minute
	// maxBackoffJitterSeconds is the maximum jitter to subtract from the max backoff.
	// The final backoff should be between (maxBackoff - maxBackoffJitterSeconds) and maxBackoff.
	maxBackoffJitterSeconds = 300 // 5 minutes jitter on max sleep

)

// withRetries adds retries with exponential backoff to a credential process.
func withRetries(process credentialProcess) credentialProcess {
	return func(opts *CredentialsOpts, signer Signer, signatureAlgorithm string) (CredentialProcessOutput, error) {
		return retryCredentialProcessWithBackoff(process, opts, signer, signatureAlgorithm)
	}
}

// retryCredentialProcessWithBackoff retries the credential process with a backoff if there are errors.
// It will never return an error, this is only to satisfy the credentialProcess signature.
func retryCredentialProcessWithBackoff(
	process credentialProcess, opts *CredentialsOpts, signer Signer, signatureAlgorithm string,
) (CredentialProcessOutput, error) {
	retries := 0
	for {
		creds, err := process(opts, signer, signatureAlgorithm)
		if err == nil {
			return creds, nil
		}

		log.Printf("Error refreshing credentials on retry %d: %s\n", retries, err)

		retries++
		wait := backoffDuration(err, retries)
		log.Printf("Retrying in %s\n", wait)
		time.Sleep(wait)
	}
}

// backoffDuration returns the duration to wait before retrying a request based on the type of error
// and the number of retries. It uses exponential backoff with jitter. Some errors, like access denied
// or validation issues, are considered non-transient and will trigger a long wait.
func backoffDuration(err error, retries int) time.Duration {
	var backoff time.Duration
	var awsErr awserr.Error
	if isAwsErr := errors.As(err, &awsErr); isAwsErr {
		switch awsErr.Code() {
		case rolesanywhere.ErrCodeAccessDeniedException, rolesanywhere.ErrCodeValidationException:
			// If we got access denied or a validation issue, this is most probably
			// a configuration issue and not a transient error. We jump straight to
			// a long wait given this unlikely to resolve itself.
			backoff = longWait()
		default:
			// If we got a resource not found or other aws errors, this is most probably
			// a configuration issue. However, given not found errors can be transient
			// due to eventual consistency, we use a we still use a exponential backoff,
			// but with a faster initial rate than the default.
			backoff = waitWithFastExpBackoff(retries)
		}
	} else {
		// For non AWS errors, we use the default exponential backoff.
		backoff = waitWithDefaultExpBackoff(retries)
	}

	if backoff > maxBackoff {
		// Backoff maxes out at 30 minutes.
		// If greater than that, get something random between 25 and 30 minutes.
		backoff = longWait()
	}

	return backoff
}

// waitWithFastExpBackoff returns duration equal to 2^retries seconds with up to
// a 20% of it value as jitter. The jitter is added in order to avoid many clients
// getting synchronized by some situation. If they all retry at
// once, they will all send requests in synchronized waves.
func waitWithDefaultExpBackoff(retries int) time.Duration {
	return expBackoffWithPadding(retries, 0)
}

// waitWithFastExpBackoff returns duration equal to 2^retries seconds with up to
// a 20% of it value as jitter plus additional 20 seconds. The jitter is added in order
// to avoid many clients getting synchronized by some situation. If they all retry at
// once, they will all send requests in synchronized waves.
func waitWithFastExpBackoff(retries int) time.Duration {
	return expBackoffWithPadding(retries, 20)
}

// expBackoffWithPadding returns duration equal to 2^retries seconds with up to
// a 20% of it value as jitter plus additional padding. The jitter added in order
// to avoid many clients getting synchronized by some situation. If they all retry at
// once, they will all send requests in synchronized waves.
// The padding is useful to allow for an increased base backoff, in case the error is
// suspected to be non-transient.
func expBackoffWithPadding(retries int, paddingSeconds int64) time.Duration {
	expBackoff := math.Pow(2, float64(retries))
	waitInSeconds := int64(expBackoff) + rand.Int63n(int64(math.Ceil(expBackoff*0.2))) + paddingSeconds
	return time.Duration(waitInSeconds) * time.Second
}

// longWait returns a random duration between 25 and 30 minutes.
func longWait() time.Duration {
	return maxBackoff - (time.Duration(rand.Int63n(maxBackoffJitterSeconds)) * time.Second)
}
