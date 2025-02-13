package context

import (
	"context"
	"time"

	"github.com/aws/smithy-go/middleware"
)

type checksumInputAlgorithmKey struct{}
type clockSkew struct{}

// SetChecksumInputAlgorithm sets the request checksum algorithm on the
// context.
func SetChecksumInputAlgorithm(ctx context.Context, value string) context.Context {
	return middleware.WithStackValue(ctx, checksumInputAlgorithmKey{}, value)
}

// GetChecksumInputAlgorithm returns the checksum algorithm from the context.
func GetChecksumInputAlgorithm(ctx context.Context) string {
	v, _ := middleware.GetStackValue(ctx, checksumInputAlgorithmKey{}).(string)
	return v
}

// SetAttemptSkewContext sets the clock skew value on the context
func SetAttemptSkewContext(ctx context.Context, v time.Duration) context.Context {
	return middleware.WithStackValue(ctx, clockSkew{}, v)
}

// GetAttemptSkewContext gets the clock skew value from the context
func GetAttemptSkewContext(ctx context.Context) time.Duration {
	x, _ := middleware.GetStackValue(ctx, clockSkew{}).(time.Duration)
	return x
}
