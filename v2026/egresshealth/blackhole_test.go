package egresshealth

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// stubDests builds a connectivity table pointed at one server, plus a
// non-connectivity entry that must never be drawn.
func stubDests(url string, n int) []Destination {
	dests := []Destination{{
		Name: "not-connectivity", Class: ClassCDN, URL: url + "/cdn",
		Expect: ExpectStatus, Status: http.StatusNoContent,
	}}
	for i := 0; i < n; i++ {
		dests = append(dests, Destination{
			Name:  "conn-" + string(rune('a'+i)),
			Class: ClassConnectivity,
			URL:   url + "/conn",
			// the real connectivity entries are 204 probes
			Expect: ExpectStatus, Status: http.StatusNoContent,
		})
	}
	return dests
}

// A provider that carries traffic passes, but the whole small sample is still
// checked so an unrelated first success cannot hide a later TLS integrity
// failure.
func TestBlackholePassesAfterCheckingIntegrityOfWholeSample(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := blackhole(context.Background(), srv.Client(), stubDests(srv.URL, 3),
		Options{Rand: rand.New(rand.NewSource(1))})

	if !res.OK {
		t.Fatalf("OK = false, want true: every destination answered correctly")
	}
	if res.Failure != "" {
		t.Errorf("Failure = %q, want empty on success", res.Failure)
	}
	if got := requests.Load(); got != BlackholeSampleSize {
		t.Errorf("made %d requests, want %d: every sampled TLS identity must be checked", got, BlackholeSampleSize)
	}
}

// Checking the whole integrity sample must not multiply the per-provider
// deadline by three. All three requests share one tunnel and can run together;
// this barrier proves they are admitted before any one is allowed to finish.
func TestBlackholeChecksIntegritySampleConcurrently(t *testing.T) {
	entered := make(chan struct{}, BlackholeSampleSize)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	done := make(chan *BlackholeResult, 1)
	go func() {
		done <- blackhole(context.Background(), srv.Client(), stubDests(srv.URL, BlackholeSampleSize),
			Options{Rand: rand.New(rand.NewSource(1)), PerRequestTimeout: 2 * time.Second})
	}()
	for i := 0; i < BlackholeSampleSize; i++ {
		select {
		case <-entered:
		case <-time.After(500 * time.Millisecond):
			close(release)
			t.Fatalf("only %d/%d checks entered before completion; the sample is running sequentially", i, BlackholeSampleSize)
		}
	}
	close(release)
	if res := <-done; !res.OK {
		t.Fatalf("concurrent healthy sample failed: %+v", res)
	}
}

// A blackhole fails only when EVERY drawn destination fails.
func TestBlackholeFailsOnlyWhenAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// a captive-portal shaped answer: 200 with a body where 204 was required
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hijacked"))
	}))
	defer srv.Close()

	res := blackhole(context.Background(), srv.Client(), stubDests(srv.URL, 3),
		Options{Rand: rand.New(rand.NewSource(1))})

	if res.OK {
		t.Fatalf("OK = true, want false: no destination met its contract")
	}
	if res.Failure != FailureAllDestinationsFailed {
		t.Errorf("Failure = %q, want %q", res.Failure, FailureAllDestinationsFailed)
	}
	if len(res.Results) != BlackholeSampleSize {
		t.Errorf("tried %d destinations, want the full sample of %d before declaring a blackhole",
			len(res.Results), BlackholeSampleSize)
	}
}

// One reachable destination among failures is NOT a blackhole. A provider
// reaching some destinations is degraded, which is Check's department -- calling
// it dark here would remove working providers on a signal that cannot tell the
// two apart.
func TestBlackholePartialReachabilityIsNotABlackhole(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := blackhole(context.Background(), srv.Client(), stubDests(srv.URL, 3),
		Options{Rand: rand.New(rand.NewSource(1))})

	if !res.OK {
		t.Errorf("OK = false, want true: the third destination answered, so traffic is getting through")
	}
}

// A successful first destination must not hide a forged TLS certificate on a
// later canary. This is the exact production failure: the old any-success loop
// returned immediately, so a TLS-intercepting provider could be recorded OK
// before the sampled gstatic destination was ever attempted.
func TestBlackholeTLSAuthenticationFailureOverridesSuccess(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()
	intercepted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer intercepted.Close()

	dests := []Destination{
		{Name: "good-a", Class: ClassConnectivity, URL: good.URL, Expect: ExpectStatus, Status: http.StatusNoContent},
		{Name: "intercepted", Class: ClassConnectivity, URL: intercepted.URL, Expect: ExpectStatus, Status: http.StatusNoContent},
		{Name: "good-b", Class: ClassConnectivity, URL: good.URL, Expect: ExpectStatus, Status: http.StatusNoContent},
	}
	res := blackhole(context.Background(), http.DefaultClient, dests,
		Options{Rand: rand.New(rand.NewSource(1)), PerRequestTimeout: time.Second})

	if res.OK {
		t.Fatal("OK = true, want false: a forged certificate is a hard provider failure")
	}
	if res.Failure != FailureTLSAuthentication {
		t.Fatalf("Failure = %q, want %q", res.Failure, FailureTLSAuthentication)
	}
	if len(res.Results) < 2 {
		t.Fatalf("tried only %d destinations: an ordinary success still ended the integrity check early", len(res.Results))
	}
}

// Only the connectivity class is ever drawn.
func TestBlackholeSampleDrawsConnectivityOnly(t *testing.T) {
	sample := blackholeSample(stubDests("http://x", 5), rand.New(rand.NewSource(7)))

	if len(sample) != BlackholeSampleSize {
		t.Fatalf("drew %d, want %d", len(sample), BlackholeSampleSize)
	}
	for _, d := range sample {
		if d.Class != ClassConnectivity {
			t.Errorf("drew %s from class %q, want %q only", d.Name, d.Class, ClassConnectivity)
		}
	}
}

// The real table must actually contain connectivity destinations, or the check
// silently degrades to "no sample, therefore a blackhole" and would condemn the
// entire fleet.
func TestBlackholeRealTableHasConnectivityDestinations(t *testing.T) {
	sample := blackholeSample(Destinations(), rand.New(rand.NewSource(1)))
	if len(sample) == 0 {
		t.Fatal("the real destination table drew no connectivity destinations: " +
			"every provider would be recorded as a blackhole")
	}
	if hosts := BlackholeHosts(); len(hosts) == 0 {
		t.Error("BlackholeHosts() is empty: the confinement self-check would not cover " +
			"the addresses this check dials, so a prober that could reach them directly would record every provider as ok")
	}
}
