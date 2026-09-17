package prober

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
	"github.com/urnetwork/operator-proxy/v2026/geolocate"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	flags := log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return buf
}

// healthResult is a provider whose tunnel works, which two CDNs refuse, and
// which two reputation vendors treat as a datacenter -- the ordinary shape of a
// hosted provider. The reputation failures must show in the log line and must
// NOT be inside ok=N/M.
//
// It is shaped like a SAMPLED run, which is what a real one is: the tallies are
// over the destinations this run drew, and TableTotal is what they were drawn
// from. A reader of the log line has to be able to tell dns=3/3 (three of a
// hundred-and-forty-entry table, drawn today) from a three-entry class.
func healthResult() *egresshealth.Result {
	return &egresshealth.Result{
		Checks: []egresshealth.CheckResult{
			{Name: "cloudflare-doh", Class: egresshealth.ClassDNS, OK: true},
			{Name: "google-doh", Class: egresshealth.ClassDNS, OK: true},
			{Name: "adguard-doh", Class: egresshealth.ClassDNS, OK: true},
			{Name: "google-generate-204", Class: egresshealth.ClassConnectivity, OK: true},
			{Name: "cloudflare-cp-204", Class: egresshealth.ClassConnectivity, OK: true},
			{Name: "cloudflare-cdn", Class: egresshealth.ClassCDN, OK: true},
			{Name: "jsdelivr-fastly-mirror", Class: egresshealth.ClassCDN},
			{Name: "amazon-cloudfront", Class: egresshealth.ClassCDN},
			{Name: "wikipedia", Class: egresshealth.ClassSite, OK: true},
			{Name: "github", Class: egresshealth.ClassSite, OK: true},
			{Name: "naver", Class: egresshealth.ClassSite, OK: true},
			{Name: "akamai", Class: egresshealth.ClassReputation},
			{Name: "etsy", Class: egresshealth.ClassReputation},
			{Name: "reddit", Class: egresshealth.ClassReputation, OK: true},
		},
		OKCount: 9,
		Total:   11,
		ByClass: map[egresshealth.Class]egresshealth.ClassSummary{
			egresshealth.ClassDNS:          {OK: 3, Total: 3},
			egresshealth.ClassConnectivity: {OK: 2, Total: 2},
			egresshealth.ClassCDN:          {OK: 1, Total: 3},
			egresshealth.ClassSite:         {OK: 3, Total: 3},
		},
		Reputation: egresshealth.ClassSummary{OK: 1, Total: 3},
		TableTotal: 140,
	}
}

// TestEgressHealthRunsOnTheSameTunnelClient is the property the whole wiring
// turns on: the check must reuse the client the tunnel already handed back, not
// prompt a second tunnel (double the contract cost, and a different session
// from the one the geolocation verdict describes).
func TestEgressHealthRunsOnTheSameTunnelClient(t *testing.T) {
	logs := captureLog(t)
	tunnelClient := &http.Client{}
	opens := 0
	var seen *http.Client

	sub := &stubSubmitter{}
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			opens++
			return tunnelClient, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: sub,
		Health: func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			seen = c
			return healthResult(), nil
		},
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	if opens != 1 {
		t.Fatalf("tunnels opened = %d, want exactly 1; the health check must not open its own", opens)
	}
	if seen != tunnelClient {
		t.Fatal("the health check ran on a different client than the tunnel's")
	}

	// The reputation figure rides alongside ok=N/M and its failures are listed
	// under their own key: 9/11 is the health verdict, and the two vendors that
	// refused the exit do not subtract from it.
	want := "egress-health: provider=provider-1 ok=9/11 dns=3/3 connectivity=2/2 cdn=1/3 site=3/3 reputation=1/3 table=140 failed=jsdelivr-fastly-mirror,amazon-cloudfront reputation-failed=akamai,etsy"
	if got := strings.TrimSpace(logs.String()); got != want {
		t.Fatalf("log line =\n%q\nwant\n%q", got, want)
	}
}

// TestEgressHealthRunsEvenWhenGeolocationFailed: the provider whose geolocation
// failed is exactly the one whose egress pattern is worth having.
func TestEgressHealthRunsEvenWhenGeolocationFailed(t *testing.T) {
	logs := captureLog(t)
	ran := false
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, geolocate.ErrNoConsensus
		},
		Submit: &stubSubmitter{},
		Health: func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			ran = true
			return healthResult(), nil
		},
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); !errors.Is(err, geolocate.ErrNoConsensus) {
		t.Fatalf("err = %v, want ErrNoConsensus", err)
	}
	if !ran {
		t.Fatal("the health check did not run after a failed geolocation; that is the case it is most useful in")
	}
	if !strings.Contains(logs.String(), "egress-health: provider=provider-1") {
		t.Fatalf("no health line logged.\n--- log ---\n%s", logs.String())
	}
}

// TestEgressHealthNeverChangesTheProbeOutcome: the failure classes reported to
// the server describe geolocation. A diagnostic must not be able to rewrite the
// record of whether a location was obtained.
func TestEgressHealthNeverChangesTheProbeOutcome(t *testing.T) {
	captureLog(t)
	sub := &stubSubmitter{}
	rep := &stubAttemptReporter{}
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit:   sub,
		Attempts: rep,
		Health: func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			return nil, errors.New("health check exploded")
		},
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("a failing health check must not fail the probe: %v", err)
	}
	if sub.calls != 1 {
		t.Fatalf("submit calls = %d, want 1", sub.calls)
	}
	if got := rep.failures(); len(got) != 1 || got[0] != "" {
		t.Fatalf("reported failure classes = %v, want one success (\"\")", got)
	}
}

// TestEgressHealthStructuralFailureIsNotLoggedAsAScore: a check that did not
// run must not be rendered as ok=0/N, which is the blackhole reading. Framing
// the prober's own fault as the provider's is how a good provider gets a bad
// record.
func TestEgressHealthStructuralFailureIsNotLoggedAsAScore(t *testing.T) {
	logs := captureLog(t)
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: &stubSubmitter{},
		Health: func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			return nil, egresshealth.ErrNilClient
		},
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "did not run") {
		t.Fatalf("a structural health failure was not reported as such.\n--- log ---\n%s", out)
	}
	if strings.Contains(out, "ok=0/") {
		t.Fatalf("a health check that never ran was logged as a zero score.\n--- log ---\n%s", out)
	}
}

// TestEgressHealthSkippedWhenNoBudgetLeft: same defect, reached the other way.
// If the probe's context is already done, a run would report 0/N for reasons
// that have nothing to do with the provider.
func TestEgressHealthSkippedWhenNoBudgetLeft(t *testing.T) {
	logs := captureLog(t)
	ran := false
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, context.DeadlineExceeded
		},
		Submit: &stubSubmitter{},
		Health: func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			ran = true
			return healthResult(), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = p.ProbeOne(ctx, "provider-1")

	if ran {
		t.Fatal("the health check ran on an already-dead context; it would report 0/N and read as a blackhole")
	}
	out := logs.String()
	if !strings.Contains(out, "skipped") {
		t.Fatalf("the skip was not logged.\n--- log ---\n%s", out)
	}
	if strings.Contains(out, "ok=0/") {
		t.Fatalf("a skipped health check was logged as a zero score.\n--- log ---\n%s", out)
	}
}

// TestNilHealthCheckerIsSkipped: the hook is optional, and a prober without it
// must behave exactly as before.
func TestNilHealthCheckerIsSkipped(t *testing.T) {
	logs := captureLog(t)
	sub := &stubSubmitter{}
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: sub,
	}
	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	if strings.Contains(logs.String(), "egress-health") {
		t.Fatalf("a nil health checker logged something.\n--- log ---\n%s", logs.String())
	}
}

// stubAttemptReporter records the failure class of every reported attempt.
type stubAttemptReporter struct {
	mu   sync.Mutex
	seen []string
}

func (s *stubAttemptReporter) ReportAttempt(ctx context.Context, id string, failure string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, failure)
	return nil
}

func (s *stubAttemptReporter) failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}
