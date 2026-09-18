package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/bandwidth"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
	"github.com/urnetwork/operator-proxy/v2026/prober"
	"github.com/urnetwork/operator-proxy/v2026/providertunnel"
)

type stubDueLister struct {
	ids   []string
	err   error
	calls int
}

func (s *stubDueLister) Due(ctx context.Context, limit int) ([]string, error) {
	s.calls++
	return s.ids, s.err
}

// enumerationServer stands in for the old enumeration path: one location, one
// provider. It records whether it was called at all, which is what the 401
// test asserts on.
func enumerationServer(t *testing.T, called *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/network/provider-locations":
			_, _ = w.Write([]byte(`{"locations":[{"location_id":"loc-1"}]}`))
		case "/network/find-providers2":
			_, _ = w.Write([]byte(`{"providers":[{"client_id":"enumerated-1"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSelectProvidersUsesTheServerDueList(t *testing.T) {
	var enumCalled bool
	srv := enumerationServer(t, &enumCalled)
	defer srv.Close()

	due := &stubDueLister{ids: []string{"due-1", "due-2"}}
	ids, serverDriven, err := selectProviders(context.Background(), due, 100, srv.URL, "jwt")
	if err != nil {
		t.Fatalf("selectProviders err = %v", err)
	}
	if !serverDriven {
		t.Error("serverDriven = false, want true when the due endpoint answered")
	}
	if len(ids) != 2 || ids[0] != "due-1" {
		t.Fatalf("ids = %v, want the server's due list", ids)
	}
	if enumCalled {
		t.Error("the enumeration path ran even though the server supplied a due list")
	}
}

// TestSelectProvidersFallsBackWhenTheEndpointIsMissing keeps the prober working
// against a server that has not deployed the due endpoint.
func TestSelectProvidersFallsBackWhenTheEndpointIsMissing(t *testing.T) {
	var enumCalled bool
	srv := enumerationServer(t, &enumCalled)
	defer srv.Close()

	due := &stubDueLister{err: ingest.ErrDueUnsupported}
	ids, serverDriven, err := selectProviders(context.Background(), due, 100, srv.URL, "jwt")
	if err != nil {
		t.Fatalf("selectProviders err = %v", err)
	}
	if serverDriven {
		t.Error("serverDriven = true, want false on the fallback path")
	}
	if !enumCalled {
		t.Fatal("the enumeration fallback did not run; the prober would do nothing against an older server")
	}
	if len(ids) != 1 || ids[0] != "enumerated-1" {
		t.Fatalf("ids = %v, want the enumerated provider", ids)
	}
}

// TestSelectProvidersDoesNotFallBackOnUnauthorized: a 401 is a wrong operator
// secret, not an old server. Falling back would hide a misconfigured
// deployment behind a full-looking pass whose every submission is then
// rejected by that same secret.
func TestSelectProvidersDoesNotFallBackOnUnauthorized(t *testing.T) {
	var enumCalled bool
	srv := enumerationServer(t, &enumCalled)
	defer srv.Close()

	due := &stubDueLister{err: ingest.ErrUnauthorized}
	_, _, err := selectProviders(context.Background(), due, 100, srv.URL, "jwt")
	if !errors.Is(err, ingest.ErrUnauthorized) {
		t.Fatalf("selectProviders err = %v, want ErrUnauthorized surfaced", err)
	}
	if enumCalled {
		t.Fatal("selectProviders fell back to enumeration on a 401; a bad secret must be loud, not silently degraded")
	}
}

// TestSelectProvidersDoesNotFallBackOnOtherErrors: a transient 500 or a dropped
// connection is not "this server is old". Falling back would mask a broken
// server behind an expensive full enumeration on every pass.
func TestSelectProvidersDoesNotFallBackOnOtherErrors(t *testing.T) {
	var enumCalled bool
	srv := enumerationServer(t, &enumCalled)
	defer srv.Close()

	due := &stubDueLister{err: errors.New("status 500")}
	if _, _, err := selectProviders(context.Background(), due, 100, srv.URL, "jwt"); err == nil {
		t.Fatal("selectProviders swallowed a due-endpoint error")
	}
	if enumCalled {
		t.Fatal("selectProviders fell back to enumeration on a non-404 error")
	}
}

// TestServerDrivenSchedulerIgnoresTheLocalTTL: when the server picks the batch
// it owns the schedule -- observed_at and attempt_at in the database, which
// survive a restart. Re-filtering that batch through the in-memory ttl would
// drop providers the server just said were due, and the two schedules would
// disagree with no way to tell which won.
func TestServerDrivenSchedulerIgnoresTheLocalTTL(t *testing.T) {
	dueScheduler, enumScheduler := newSchedulers(&prober.Prober{}, 4, 24*time.Hour)
	if dueScheduler.CacheTTL != 0 {
		t.Errorf("server-driven scheduler CacheTTL = %s, want 0 (the server owns the schedule)", dueScheduler.CacheTTL)
	}
	if enumScheduler.CacheTTL != 24*time.Hour {
		t.Errorf("fallback scheduler CacheTTL = %s, want the configured -cache-ttl", enumScheduler.CacheTTL)
	}
	if dueScheduler == enumScheduler {
		t.Error("the two schedulers must be distinct so the fallback keeps its own cache")
	}
}

// TestNewProberReportsAttempts: the prober the CLI actually builds must have an
// attempt reporter. Without one the server's starvation fix is inert -- every
// provider that always fails to probe stays at the head of the due queue
// forever, and nothing about the pass output would say so.
func TestNewProberReportsAttempts(t *testing.T) {
	operator := &ingest.Client{ServerURL: "http://unused.invalid"}
	p := newProber(providertunnel.Config{}, &pinSet{}, time.Minute, operator, false, nil, nil)
	if p.Attempts == nil {
		t.Fatal("newProber built a Prober with no attempt reporter; the server-side due backoff would never be told a probe happened")
	}
	if p.Submit == nil || p.Open == nil || p.Locate == nil {
		t.Fatal("newProber left a dependency unset")
	}
	// HealthResults too: without it the health check still runs and still
	// logs, so every test here would pass while the results reached no
	// server at all -- which is the whole point of submitting them.
	if p.HealthResults == nil {
		t.Fatal("newProber built a Prober with no health-result submitter; health would be logged and never persisted")
	}
	if p.Bandwidth != nil {
		t.Error("a nil sampler (-skip-bandwidth) must leave the bandwidth hook unset, not install one that measures nothing")
	}
}

// TestNewProberWiresBandwidthWhenEnabled: with a sampler configured the hook
// has to be installed, or every provider is probed for geolocation and none is
// ever measured -- silently, since nothing else in the pass output would say so.
func TestNewProberWiresBandwidthWhenEnabled(t *testing.T) {
	operator := &ingest.Client{ServerURL: "http://unused.invalid"}
	targets := bandwidth.DefaultTargets("https://api.example.net", "secret")
	sampler := &bandwidth.Sampler{Targets: targets, Reserve: operator, Submit: operator}

	p := newProber(providertunnel.Config{}, &pinSet{}, time.Minute, operator, false, sampler, bandwidth.TargetHosts(targets))
	if p.Bandwidth == nil {
		t.Fatal("newProber did not install the bandwidth hook, so no provider would ever be measured")
	}
	if len(sampler.Targets) != 2 {
		t.Fatalf("the production sampler has %d targets, want 2 (operator and cdn) -- one target cannot show a provider prioritising one path over the other", len(sampler.Targets))
	}
	if sampler.Targets[0].Source == sampler.Targets[1].Source {
		t.Errorf("both targets carry source %q; they must be stored separately", sampler.Targets[0].Source)
	}
}

// TestDueLimitIsSentToTheServer guards the flag actually reaching the wire.
func TestDueLimitIsSentToTheServer(t *testing.T) {
	var gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		_ = json.NewEncoder(w).Encode(map[string][]string{"client_ids": {}})
	}))
	defer srv.Close()

	c := &ingest.Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	if _, _, err := selectProviders(context.Background(), c, 42, srv.URL, "jwt"); err != nil {
		t.Fatalf("selectProviders err = %v", err)
	}
	if gotLimit != "42" {
		t.Fatalf("limit = %q, want 42", gotLimit)
	}
}
