package fleetprobe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/providertunnel"
)

type pinFailureRoundTripper func(*http.Request) (*http.Response, error)

func (self pinFailureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

func TestFullProberClassifiesTypedPinFailureWithoutRawDetail(t *testing.T) {
	providerProber := NewFullProber(FullOptions{ProbeTimeout: time.Minute})
	client := &http.Client{Transport: pinFailureRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("private certificate and host detail: %w", providertunnel.ErrPinMismatch)
	})}
	_, err := providerProber.Locate(context.Background(), client)
	if !errors.Is(err, geolocate.ErrNoConsensus) {
		t.Fatalf("err = %v, want ErrNoConsensus", err)
	}
	diagnostics := geolocate.SourceDiagnostics(err)
	if len(diagnostics) != 3 {
		t.Fatalf("diagnostics = %d, want one for each configured source", len(diagnostics))
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Class != geolocate.SourceDiagnosticTLSOrPin || diagnostic.Stage != geolocate.SourceDiagnosticStageTLS {
			t.Errorf("pin diagnostic = %+v, want tls_or_pin/tls", diagnostic)
		}
	}
	if got := fmt.Sprintf("%v %+v", err, diagnostics); strings.Contains(got, "private") {
		t.Fatalf("diagnostic leaked raw pin detail: %s", got)
	}
}
