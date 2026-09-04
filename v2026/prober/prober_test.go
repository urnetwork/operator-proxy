package prober

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/operator-proxy/v2026/geolocate"
)

// stubSubmitter is shared by prober_test.go (single-goroutine callers) and
// schedule_test.go (concurrent callers via Scheduler.Run), so its fields must
// be safe for concurrent access.
type stubSubmitter struct {
	mu    sync.Mutex
	calls int
	last  *geolocate.ConsensusLocation
	err   error
}

func (s *stubSubmitter) Submit(ctx context.Context, id string, loc *geolocate.ConsensusLocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.last = loc
	return s.err
}

func TestProbeOneHappyPathSubmitsAndCloses(t *testing.T) {
	closed := false
	sub := &stubSubmitter{}
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { closed = true; return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: sub,
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	if sub.calls != 1 {
		t.Fatalf("submit calls = %d, want 1", sub.calls)
	}
	if !closed {
		t.Fatal("the tunnel must be closed after the probe")
	}
}

func TestProbeOneNoConsensusDoesNotSubmit(t *testing.T) {
	closed := false
	sub := &stubSubmitter{}
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { closed = true; return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, geolocate.ErrNoConsensus
		},
		Submit: sub,
	}
	err := p.ProbeOne(context.Background(), "provider-1")
	if !errors.Is(err, geolocate.ErrNoConsensus) {
		t.Fatalf("err = %v, want ErrNoConsensus", err)
	}
	if sub.calls != 0 {
		t.Fatal("must not submit without consensus")
	}
	if !closed {
		t.Fatal("the tunnel must be closed even when the probe fails")
	}
}

// TestProbeOneTunnelFailureSkipsLocateAndSubmit: a tunnel that will not open
// must short-circuit the probe. (The ATTEMPT reporting for this case is
// covered by TestProbeOneReportsATunnelFailure in attempt_test.go, which
// wires a reporter; this test deliberately has none, so its old name promised
// an assertion it never made.)
func TestProbeOneTunnelFailureSkipsLocateAndSubmit(t *testing.T) {
	sub := &stubSubmitter{}
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return nil, nil, errors.New("no route to provider")
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			t.Fatal("Locate must not run when the tunnel fails")
			return nil, nil
		},
		Submit: sub,
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); err == nil {
		t.Fatal("expected a tunnel error")
	}
	if sub.calls != 0 {
		t.Fatal("must not submit when the tunnel fails")
	}
}
