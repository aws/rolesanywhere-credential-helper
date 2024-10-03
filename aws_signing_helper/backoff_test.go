package aws_signing_helper

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
)

func TestBackoffDuration(t *testing.T) {
	testCases := []struct {
		name                           string
		err                            error
		retries                        int
		wantUpperBound, wantLowerBound time.Duration
	}{
		{
			name:           "no aws error, 0 retries",
			err:            errors.New("non aws error"),
			retries:        0,
			wantLowerBound: 1 * time.Second,
			wantUpperBound: 1200 * time.Millisecond,
		},
		{
			name:           "no aws error, 1 retries",
			err:            errors.New("non aws error"),
			retries:        1,
			wantLowerBound: 2 * time.Second,
			wantUpperBound: 2400 * time.Millisecond,
		},
		{
			name:           "no aws error, 2 retries",
			err:            errors.New("non aws error"),
			retries:        2,
			wantLowerBound: 4 * time.Second,
			wantUpperBound: 4800 * time.Millisecond,
		},
		{
			name:           "no aws error, 10 retries",
			err:            errors.New("non aws error"),
			retries:        10,
			wantLowerBound: 1024 * time.Second,
			wantUpperBound: 1228800 * time.Millisecond,
		},
		{
			name:           "no aws error, 11 retries, upper bound is 30 minutes",
			err:            errors.New("non aws error"),
			retries:        11,
			wantLowerBound: 25 * time.Minute,
			wantUpperBound: 30 * time.Minute,
		},

		{
			name:           "Access denied error, 0 retries",
			err:            &rolesanywhere.AccessDeniedException{},
			retries:        0,
			wantLowerBound: 25 * time.Minute,
			wantUpperBound: 30 * time.Minute,
		},
		{
			name:           "Access denied error, 5 retries",
			err:            &rolesanywhere.AccessDeniedException{},
			retries:        5,
			wantLowerBound: 25 * time.Minute,
			wantUpperBound: 30 * time.Minute,
		},

		{
			name:           "Validation error, 0 retries",
			err:            &rolesanywhere.ValidationException{},
			retries:        0,
			wantLowerBound: 25 * time.Minute,
			wantUpperBound: 30 * time.Minute,
		},
		{
			name:           "Validation error, 10 retries",
			err:            &rolesanywhere.ValidationException{},
			retries:        5,
			wantLowerBound: 25 * time.Minute,
			wantUpperBound: 30 * time.Minute,
		},

		{
			name:           "other aws error, 0 retries",
			err:            &rolesanywhere.ResourceNotFoundException{},
			retries:        0,
			wantLowerBound: 21 * time.Second,
			wantUpperBound: 21200 * time.Millisecond,
		},
		{
			name:           "other aws error, 1 retries",
			err:            &rolesanywhere.ResourceNotFoundException{},
			retries:        1,
			wantLowerBound: 22 * time.Second,
			wantUpperBound: 22400 * time.Millisecond,
		},
		{
			name:           "other aws error, 2 retries",
			err:            &rolesanywhere.ResourceNotFoundException{},
			retries:        2,
			wantLowerBound: 24 * time.Second,
			wantUpperBound: 24800 * time.Millisecond,
		},
		{
			name:           "other aws error, 10 retries",
			err:            awserr.New("generic", "aws error", errors.New("")),
			retries:        10,
			wantLowerBound: 1044 * time.Second,
			wantUpperBound: 1248800 * time.Millisecond,
		},
		{
			name:           "other aws error, 11 retries, upper bound is 30 minutes",
			err:            awserr.New("generic", "aws error", errors.New("")),
			retries:        11,
			wantLowerBound: 25 * time.Minute,
			wantUpperBound: 30 * time.Minute,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := backoffDuration(tc.err, tc.retries)
			if got > 30*time.Minute {
				t.Errorf("backoffDuration() = %v; want <= %v", got, 30*time.Minute)
			}
			if got < tc.wantLowerBound {
				t.Errorf("backoffDuration() = %v; want >= %v", got, tc.wantLowerBound)
			}
			if got > tc.wantUpperBound {
				t.Errorf("backoffDuration() = %v; want <= %v", got, tc.wantUpperBound)
			}
		})
	}
}
