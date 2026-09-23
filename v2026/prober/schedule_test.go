package prober

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/geolocate"
)

func okProber(probed *int32, mu *sync.Mutex, inflight *int32, maxSeen *int32) *Prober {
	return &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			cur := atomic.AddInt32(inflight, 1)
			mu.Lock()
			if cur > *maxSeen {
				*maxSeen = cur
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			return &http.Client{}, func() error { atomic.AddInt32(inflight, -1); return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			atomic.AddInt32(probed, 1)
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: &stubSubmitter{},
	}
}

func TestSchedulerRespectsConcurrencyCap(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	s := &Scheduler{Prober: okProber(&probed, &mu, &inflight, &maxSeen), Concurrency: 2, CacheTTL: time.Hour}

	ids := []string{"a", "b", "c", "d", "e", "f"}
	sum := s.Run(context.Background(), ids)

	if sum.Attempted != len(ids) {
		t.Fatalf("attempted = %d, want %d", sum.Attempted, len(ids))
	}
	if sum.Submitted != len(ids) {
		t.Fatalf("submitted = %d, want %d", sum.Submitted, len(ids))
	}
	mu.Lock()
	peak := maxSeen
	mu.Unlock()
	if peak > 2 {
		t.Fatalf("peak concurrency = %d, want <= 2", peak)
	}
}

// TestSchedulerStopsSpawningWhenCancelled: a SIGTERM mid-pass cancels the
// run's context, and the spawn loop must stop there. providertunnel.Open
// constructs a full netstack before any context check, so without the stop
// every remaining provider in the batch still got a real tunnel built and
// torn down just so its probe could fail instantly on the dead context --
// a 500-provider batch reported hundreds of spurious failures, and
// single-shot mode exited 1 blaming the providers, when the truth was that
// the operator pressed Ctrl-C.
func TestSchedulerStopsSpawningWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opens atomic.Int32
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			opens.Add(1)
			// the operator's signal lands while the first probe is in flight
			cancel()
			return nil, nil, ctx.Err()
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, ctx.Err()
		},
		Submit: &stubSubmitter{},
	}
	var logBuf bytes.Buffer
	origWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origWriter)

	s := &Scheduler{Prober: p, Concurrency: 1, CacheTTL: time.Hour}
	ids := []string{"a", "b", "c", "d", "e"}
	sum := s.Run(ctx, ids)

	// The in-flight probe is legitimately attempted, and one more may race
	// the cancellation through the semaphore; anything beyond that means the
	// loop is not watching the context.
	if got := opens.Load(); got > 2 {
		t.Fatalf("%d tunnels were opened after the run was cancelled, want at most 2 (the in-flight probe plus at most one race)", got)
	}
	if sum.Skipped < len(ids)-2 {
		t.Fatalf("skipped = %d, want at least %d: the unspawned remainder must be accounted as skipped, not silently dropped", sum.Skipped, len(ids)-2)
	}
	if sum.Attempted+sum.Skipped != len(ids) {
		t.Fatalf("attempted (%d) + skipped (%d) != %d: every id in the batch must be accounted for", sum.Attempted, sum.Skipped, len(ids))
	}
}

func TestSchedulerCachesWithinTTL(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	s := &Scheduler{Prober: okProber(&probed, &mu, &inflight, &maxSeen), Concurrency: 2, CacheTTL: time.Hour}

	s.Run(context.Background(), []string{"a", "b"})
	first := atomic.LoadInt32(&probed)
	sum := s.Run(context.Background(), []string{"a", "b"})

	if atomic.LoadInt32(&probed) != first {
		t.Fatal("a second run within the ttl must not re-probe")
	}
	if sum.Skipped != 2 {
		t.Fatalf("skipped = %d, want 2", sum.Skipped)
	}
}

func TestSchedulerReprobesAfterTTL(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	now := time.Now()
	s := &Scheduler{
		Prober:      okProber(&probed, &mu, &inflight, &maxSeen),
		Concurrency: 2,
		CacheTTL:    time.Hour,
		Now:         func() time.Time { return now },
	}
	s.Run(context.Background(), []string{"a"})
	now = now.Add(2 * time.Hour)
	s.Run(context.Background(), []string{"a"})

	if atomic.LoadInt32(&probed) != 2 {
		t.Fatalf("probed = %d, want 2 (ttl expired)", probed)
	}
}

// TestSchedulerPrunesProbedAfterTTL is the M2 regression test: probed must
// not grow unboundedly across the life of a long-running Scheduler. An
// entry past CacheTTL no longer affects recentlyProbed's decision either
// way, but it must still be evicted from the map so memory does not
// accumulate one entry per provider ever probed, forever, in a process
// that runs an unbounded number of passes (cmd/egress-prober's main loop).
// This drives Run with an EMPTY id list on the second call specifically to
// isolate pruning from re-probing: nothing is attempted or skipped, so any
// change to probed's size can only be prune's doing.
func TestSchedulerPrunesProbedAfterTTL(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	now := time.Now()
	s := &Scheduler{
		Prober:      okProber(&probed, &mu, &inflight, &maxSeen),
		Concurrency: 2,
		CacheTTL:    time.Hour,
		Now:         func() time.Time { return now },
	}
	s.Run(context.Background(), []string{"a", "b"})

	s.mu.Lock()
	before := len(s.probed)
	s.mu.Unlock()
	if before != 2 {
		t.Fatalf("probed entries after first run = %d, want 2", before)
	}

	now = now.Add(2 * time.Hour)
	s.Run(context.Background(), nil)

	s.mu.Lock()
	after := len(s.probed)
	s.mu.Unlock()
	if after != 0 {
		t.Fatalf("probed entries after TTL elapsed = %d, want 0 (stale entries must be pruned)", after)
	}
}

func TestSchedulerCountsFailuresAndDoesNotCache(t *testing.T) {
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return nil, nil, errors.New("boom")
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, nil
		},
		Submit: &stubSubmitter{},
	}
	s := &Scheduler{Prober: p, Concurrency: 1, CacheTTL: time.Hour}
	sum := s.Run(context.Background(), []string{"a"})
	if sum.Failed != 1 {
		t.Fatalf("failed = %d, want 1", sum.Failed)
	}
	// a failure must not be cached; the next run retries
	sum2 := s.Run(context.Background(), []string{"a"})
	if sum2.Attempted != 1 {
		t.Fatal("a failed probe must be retried on the next run")
	}
}

type sourceOutcomeRoundTripper func(*http.Request) (*http.Response, error)

func (self sourceOutcomeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

func TestSchedulerEmitsOnePrivacySafeNoConsensusAggregate(t *testing.T) {
	const (
		firstProvider  = "provider-private-one"
		secondProvider = "provider-private-two"
	)
	client := &http.Client{Transport: sourceOutcomeRoundTripper(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Hostname() {
		case "api.i.pn":
			return nil, fmt.Errorf("private cold-tunnel state: %w", context.DeadlineExceeded)
		case "free.freeipapi.com":
			return &http.Response{
				StatusCode: 599,
				Body:       io.NopCloser(strings.NewReader("private response body")),
				Header:     http.Header{},
			}, nil
		case "ipinfo.io":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"country":"US"}`)),
				Header:     http.Header{},
			}, nil
		default:
			return nil, errors.New("private unexpected endpoint")
		}
	})}
	_, diagnosticErr := geolocate.LocateWithOptions(
		context.Background(), client, geolocate.LocateOptions{PerSourceTimeout: time.Minute},
	)
	if !errors.Is(diagnosticErr, geolocate.ErrNoConsensus) {
		t.Fatalf("diagnostic fixture err = %v, want ErrNoConsensus", diagnosticErr)
	}
	reporter := &stubReporter{}
	p := &Prober{
		Open: func(context.Context, string) (*http.Client, func() error, error) {
			return client, func() error { return nil }, nil
		},
		Locate: func(context.Context, *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, diagnosticErr
		},
		Submit:   &stubSubmitter{},
		Attempts: reporter,
	}

	var buf bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(originalWriter)

	summary := (&Scheduler{Prober: p, Concurrency: 2}).Run(
		context.Background(), []string{firstProvider, secondProvider},
	)
	if summary.Failed != 2 || summary.Submitted != 0 {
		t.Fatalf("summary failed/submitted = %d/%d, want 2/0", summary.Failed, summary.Submitted)
	}
	attempts := reporter.snapshot()
	if len(attempts) != 2 {
		t.Fatalf("reported attempts = %d, want 2", len(attempts))
	}
	for _, attempt := range attempts {
		if attempt.failure != FailureNoConsensus {
			t.Fatalf("probe_failure = %q, want unchanged %q", attempt.failure, FailureNoConsensus)
		}
	}
	if len(summary.GeolocationSourceOutcomes) != 3 {
		t.Fatalf("source outcome groups = %d, want 3: %+v", len(summary.GeolocationSourceOutcomes), summary.GeolocationSourceOutcomes)
	}
	want := map[string]int{
		"ip.pn/timeout/connect_formation":        2,
		"freeipapi/http_status/response_headers": 2,
		"ipinfo/success/complete":                2,
	}
	for _, outcome := range summary.GeolocationSourceOutcomes {
		key := strings.Join([]string{outcome.Source, outcome.Class, outcome.Stage}, "/")
		if outcome.Count != want[key] {
			t.Errorf("outcome %s count=%d, want %d", key, outcome.Count, want[key])
		}
		delete(want, key)
		if outcome.Elapsed == "" {
			t.Errorf("outcome %s has no bounded elapsed bucket", key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing source outcome groups: %v", want)
	}
	logged := buf.String()
	if strings.Count(logged, "geolocate-source-outcomes:") != 1 {
		t.Fatalf("safe aggregate count != 1:\n%s", logged)
	}
	if strings.Contains(logged, "probe failed provider=") {
		t.Fatalf("diagnostic-bearing no-consensus retained per-provider error detail:\n%s", logged)
	}
	for _, private := range []string{
		firstProvider, secondProvider, "private", "599", "api.i.pn", "free.freeipapi.com", "ipinfo.io", "https://",
	} {
		if strings.Contains(logged, private) {
			t.Fatalf("safe aggregate leaked %q:\n%s", private, logged)
		}
	}
}

func TestGeolocationSourceOutcomeAggregateIsDeterministicallyBounded(t *testing.T) {
	classes := []string{
		"success", "dns", "timeout", "connect", "tls_or_pin",
		"http_status", "response_read", "response_size", "parse", "request",
	}
	counts := map[geolocationSourceOutcomeKey]int{}
	nextCount := 1
	for _, source := range []string{"ip.pn", "freeipapi", "ipinfo"} {
		for _, class := range classes {
			counts[geolocationSourceOutcomeKey{
				source: source, class: class, stage: "connect_formation", elapsed: "lt1s",
			}] = nextCount
			nextCount++
		}
	}
	outcomes, omittedGroups, omittedResults := boundedGeolocationSourceOutcomes(counts)
	if len(outcomes) != maxGeolocationSourceOutcomeGroups {
		t.Fatalf("bounded groups = %d, want %d", len(outcomes), maxGeolocationSourceOutcomeGroups)
	}
	if omittedGroups != len(counts)-maxGeolocationSourceOutcomeGroups || omittedResults <= 0 {
		t.Fatalf("omitted groups/results = %d/%d, want %d/positive", omittedGroups, omittedResults, len(counts)-maxGeolocationSourceOutcomeGroups)
	}
	for index := 1; index < len(outcomes); index++ {
		if outcomes[index-1].Count < outcomes[index].Count {
			t.Fatalf("outcomes are not sorted by descending count: %+v", outcomes)
		}
	}
}

// TestSchedulerLogsCappedDistinctErrors is the I2 regression test: each
// provider here fails with a DISTINCT error message (so a naive
// once-per-message dedupe against a single global error would not
// coalesce them), and there are more of them than
// maxLoggedDistinctErrors. Run must log detail for only the first
// maxLoggedDistinctErrors distinct messages, plus exactly one suppression
// notice once the cap is hit -- not flood the log with all of them, and
// not silently drop all detail either. sum.Failed must still count every
// failure regardless of how many were logged in detail.
func TestSchedulerLogsCappedDistinctErrors(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return nil, nil, fmt.Errorf("boom-%s", id) // distinct per provider
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, nil
		},
		Submit: &stubSubmitter{},
	}

	const n = maxLoggedDistinctErrors + 5
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("p%d", i)
	}

	s := &Scheduler{Prober: p, Concurrency: 4, CacheTTL: time.Hour}
	sum := s.Run(context.Background(), ids)

	if sum.Failed != n {
		t.Fatalf("failed = %d, want %d", sum.Failed, n)
	}

	logged := buf.String()
	detailLines := strings.Count(logged, "probe failed provider=")
	if detailLines != maxLoggedDistinctErrors {
		t.Fatalf("detail lines logged = %d, want %d (the cap)", detailLines, maxLoggedDistinctErrors)
	}
	if strings.Count(logged, "suppressing further per-error detail") != 1 {
		t.Fatal("want exactly one suppression notice once the distinct-error cap was hit")
	}
}

// TestSchedulerProbesADuplicateIdOnce: recentlyProbed only becomes true once
// a probe COMPLETES, so a due batch containing the same provider twice used
// to open two tunnels to it at the same moment and pay the contract cost
// twice. The enumeration path de-duplicates before Run sees it; the due list
// is whatever the server sent.
func TestSchedulerProbesADuplicateIdOnce(t *testing.T) {
	var opens atomic.Int32
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			opens.Add(1)
			time.Sleep(10 * time.Millisecond)
			return &http.Client{}, func() error { return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: &stubSubmitter{},
	}
	s := &Scheduler{Prober: p, Concurrency: 4, CacheTTL: time.Hour}
	sum := s.Run(context.Background(), []string{"a", "a", "a"})

	if got := opens.Load(); got != 1 {
		t.Fatalf("opened %d tunnels for one repeated id, want 1", got)
	}
	if sum.Attempted != 1 || sum.Skipped != 2 {
		t.Fatalf("attempted = %d skipped = %d, want 1 and 2", sum.Attempted, sum.Skipped)
	}
}
