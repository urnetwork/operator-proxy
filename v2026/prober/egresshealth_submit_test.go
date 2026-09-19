package prober

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
)

// stubHealthReporter records what the prober handed to the health submitter.
// Safe for concurrent use, matching stubSubmitter, so a scheduler-driven test
// could reuse it.
type stubHealthReporter struct {
	mu    sync.Mutex
	calls int
	last  *egresshealth.Result
	err   error
}

func (s *stubHealthReporter) SubmitEgressHealth(ctx context.Context, id string, res *egresshealth.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.last = res
	return s.err
}

func healthProber(health EgressHealthChecker, reporter HealthReporter) *Prober {
	return &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit:        &stubSubmitter{},
		Health:        health,
		HealthResults: reporter,
	}
}

// TestEgressHealthResultIsSubmitted: the whole point of the change. The run
// used to be a log line and nothing else.
func TestEgressHealthResultIsSubmitted(t *testing.T) {
	captureLog(t)
	reporter := &stubHealthReporter{}
	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, reporter)

	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	if reporter.calls != 1 {
		t.Fatalf("SubmitEgressHealth called %d times, want 1", reporter.calls)
	}
	if reporter.last == nil || reporter.last.OKCount != 9 || reporter.last.Total != 11 {
		t.Fatalf("submitted result = %+v, want the run's own 9/11", reporter.last)
	}
}

// TestEgressHealthIsNotSubmittedWhenTheCheckDidNotRun covers both early
// returns in checkEgressHealth. Neither produces a Result, and submitting a
// zero for them would be indistinguishable from a total blackhole -- a false
// accusation against a provider whose check was skipped for the prober's own
// exhausted deadline, or that errored structurally.
func TestEgressHealthIsNotSubmittedWhenTheCheckDidNotRun(t *testing.T) {
	t.Run("structural failure", func(t *testing.T) {
		captureLog(t)
		reporter := &stubHealthReporter{}
		p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			return nil, egresshealth.ErrNilClient
		}, reporter)

		if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
			t.Fatalf("ProbeOne err = %v", err)
		}
		if reporter.calls != 0 {
			t.Fatalf("a health check that never ran was submitted (%d calls)", reporter.calls)
		}
	})

	t.Run("no budget left", func(t *testing.T) {
		captureLog(t)
		reporter := &stubHealthReporter{}
		p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
			t.Fatal("the check must not run on a dead context")
			return nil, nil
		}, reporter)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = p.ProbeOne(ctx, "provider-1")

		if reporter.calls != 0 {
			t.Fatalf("a skipped health check was submitted (%d calls)", reporter.calls)
		}
	})
}

// TestEgressHealthSubmitFailureDoesNotFailTheProbe is the fire-and-forget
// contract. The product of a pass is the geolocation; a diagnostic that could
// fail it would be worse than no diagnostic. The location has already been
// recorded server-side by the time this runs.
func TestEgressHealthSubmitFailureDoesNotFailTheProbe(t *testing.T) {
	logs := captureLog(t)
	reporter := &stubHealthReporter{err: errors.New("connection refused")}
	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, reporter)

	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("a health submission failure failed the probe: %v", err)
	}
	if !strings.Contains(logs.String(), "could not submit an egress-health result") {
		t.Fatalf("the submission failure was not logged.\n--- log ---\n%s", logs.String())
	}
	// the health line itself must still be there: the signal is logged whether
	// or not it could be stored
	if !strings.Contains(logs.String(), "ok=9/11") {
		t.Fatalf("the health line was lost when the submission failed.\n--- log ---\n%s", logs.String())
	}
}

// TestEgressHealthSubmitErrorsAreLoggedOnce: whatever stops the submissions
// getting through stops them for every provider, so a line per provider would
// bury the pass's real output under one identical line per provider, every
// pass. Same dedup contract as the attempt reporter.
func TestEgressHealthSubmitErrorsAreLoggedOnce(t *testing.T) {
	logs := captureLog(t)
	reporter := &stubHealthReporter{err: errors.New("connection refused")}
	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, reporter)

	for i := 0; i < 5; i++ {
		if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
			t.Fatalf("ProbeOne err = %v", err)
		}
	}
	if n := strings.Count(logs.String(), "could not submit an egress-health result"); n != 1 {
		t.Fatalf("the same submission error was logged %d times, want 1.\n--- log ---\n%s", n, logs.String())
	}
	if reporter.calls != 5 {
		t.Fatalf("submission was attempted %d times, want 5 -- dedup is on the LOGGING, not on the attempt", reporter.calls)
	}
}

// TestEgressHealthUnsupportedServerIsACleanSkip: a deployment that has not
// shipped the endpoint answers 404. The prober must keep working against it,
// and must say so as a skip rather than as a failure.
func TestEgressHealthUnsupportedServerIsACleanSkip(t *testing.T) {
	logs := captureLog(t)
	reporter := &stubHealthReporter{err: egresshealth.ErrUnsupported}
	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, reporter)

	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("an older server failed the probe: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "does not store egress-health results") {
		t.Fatalf("the unsupported server was not reported as a skip.\n--- log ---\n%s", out)
	}
	if strings.Contains(out, "could not submit") {
		t.Fatalf("an unsupported server was reported as a submission failure.\n--- log ---\n%s", out)
	}
}

// TestNilHealthReporterIsSkipped: the hook is optional, and a prober without
// it must behave exactly as before -- health still logged, nothing submitted.
func TestNilHealthReporterIsSkipped(t *testing.T) {
	logs := captureLog(t)
	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, nil)

	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	if !strings.Contains(logs.String(), "ok=9/11") {
		t.Fatalf("the health line was lost.\n--- log ---\n%s", logs.String())
	}
}

// TestEgressHealthReachesAnIngestStub drives the prober through a real
// *ingest.Client against an httptest server, so the body the server would
// actually receive is asserted end to end rather than at the interface
// boundary. This is the seam a field-name drift hides in: the prober submits
// fire-and-forget, so a rejected body is one log line and then permanent
// silence while nothing is stored.
//
// ingest is imported by this TEST file only -- the prober package itself
// never imports it, which is what the HealthReporter interface is for.
func TestEgressHealthReachesAnIngestStub(t *testing.T) {
	captureLog(t)

	var gotPath, gotSecret string
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, &ingest.Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()})

	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}

	if gotPath != "/network/provider-egress-health" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotSecret != "s3cret" {
		t.Fatalf("operator secret header = %q", gotSecret)
	}

	var body struct {
		ClientId     string `json:"client_id"`
		OKCount      int    `json:"ok_count"`
		TotalCount   int    `json:"total_count"`
		ClassResults map[string]struct {
			OK    int `json:"ok"`
			Total int `json:"total"`
		} `json:"class_results"`
		ReputationOK          int    `json:"reputation_ok"`
		ReputationTotal       int    `json:"reputation_total"`
		FailedNames           string `json:"failed_names"`
		ReputationFailedNames string `json:"reputation_failed_names"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal body: %s (raw = %s)", err, raw)
	}
	if body.ClientId != "provider-1" {
		t.Errorf("client_id = %q", body.ClientId)
	}
	if body.OKCount != 9 || body.TotalCount != 11 {
		t.Errorf("ok/total = %d/%d, want the scored classes only (9/11)", body.OKCount, body.TotalCount)
	}
	if body.ReputationOK != 1 || body.ReputationTotal != 3 {
		t.Errorf("reputation = %d/%d, want 1/3 reported separately", body.ReputationOK, body.ReputationTotal)
	}
	if _, present := body.ClassResults["reputation"]; present {
		t.Error("reputation was submitted as a scored class")
	}
	if len(body.ClassResults) != 4 {
		t.Errorf("class_results has %d classes, want the 4 scored ones", len(body.ClassResults))
	}
	if body.FailedNames != "jsdelivr-fastly-mirror,amazon-cloudfront" {
		t.Errorf("failed_names = %q", body.FailedNames)
	}
	if body.ReputationFailedNames != "akamai,etsy" {
		t.Errorf("reputation_failed_names = %q", body.ReputationFailedNames)
	}
}

// TestEgressHealthIngestFailureDoesNotFailThePass is the same fire-and-forget
// contract as above, reached through the real http path: a server that 500s
// must not fail a probe whose location was already recorded.
func TestEgressHealthIngestFailureDoesNotFailThePass(t *testing.T) {
	logs := captureLog(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, &ingest.Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()})

	if err := p.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("a 500 from the ingest endpoint failed the probe: %v", err)
	}
	if !strings.Contains(logs.String(), "could not submit an egress-health result") {
		t.Fatalf("the failure was not logged.\n--- log ---\n%s", logs.String())
	}

	// and the same again with nothing listening at all
	srv.Close()
	p2 := healthProber(func(ctx context.Context, c *http.Client) (*egresshealth.Result, error) {
		return healthResult(), nil
	}, &ingest.Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()})
	if err := p2.ProbeOne(context.Background(), "provider-1"); err != nil {
		t.Fatalf("a refused connection to the ingest endpoint failed the probe: %v", err)
	}
}
