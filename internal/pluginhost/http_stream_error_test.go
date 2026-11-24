package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestHTTPStreamErrorCodePreservesTypedCauses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrapped: %w", context.Canceled), "context_canceled"},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "context_deadline_exceeded"},
		{&net.DNSError{IsTimeout: true}, "transport_timeout"},
		{errors.New("private transport details"), "transport_read_failed"},
	} {
		if got := httpStreamErrorCode(tc.err); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}
