package geolocate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func jsonServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestLocateAllAgree(t *testing.T) {
	s1 := jsonServer(`{"status":"success","countryCode":"US","country":"United States","city":"Fairfax","asn":401486}`)
	defer s1.Close()
	s2 := jsonServer(`{"countryCode":"US","countryName":"United States","cityName":"Denver","regionName":"Colorado","asn":"401486","isProxy":true}`)
	defer s2.Close()
	s3 := jsonServer(`{"country":"US","city":"Atlanta","region":"Georgia","org":"AS401486 RAVNIX LLC"}`)
	defer s3.Close()

	srcs := []source{
		{Name: "ip.pn", URL: s1.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: s2.URL, Parse: parseFreeIpApi},
		{Name: "ipinfo", URL: s3.URL, Parse: parseIpInfo},
	}
	loc, err := locate(context.Background(), &http.Client{}, srcs, LocateOptions{})
	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	if !loc.CountryConfident || loc.CountryCode != "us" {
		t.Fatalf("country = %q confident=%v", loc.CountryCode, loc.CountryConfident)
	}
	if loc.CityConfident {
		t.Fatal("cities disagree; CityConfident must be false")
	}
	if loc.ASN != 401486 {
		t.Fatalf("ASN = %d", loc.ASN)
	}
	// Only freeipapi called this a proxy. A net-type flag is held to the same
	// corroboration bar as the country, so one source's say-so does not set
	// it -- see TestConsensusFlagsRequireCorroboration.
	if loc.Proxy {
		t.Fatal("Proxy was set from a single source; flags require corroboration")
	}
	if len(loc.Sources) != 3 {
		t.Fatalf("expected 3 source records, got %d", len(loc.Sources))
	}
	if loc.ProbedAt.IsZero() {
		t.Fatal("ProbedAt must be set to a non-zero time; a zero value maps to B's observed_at and gets the submission rejected")
	}
	wantNames := map[string]bool{"ip.pn": true, "freeipapi": true, "ipinfo": true}
	seenNames := map[string]bool{}
	for _, s := range loc.Sources {
		if !s.OK {
			continue
		}
		if s.Name == "" {
			t.Fatalf("successful SourceResult has empty Name: %+v", s)
		}
		if !wantNames[s.Name] {
			t.Fatalf("successful SourceResult has unexpected Name %q: %+v", s.Name, s)
		}
		seenNames[s.Name] = true
	}
	for name := range wantNames {
		if !seenNames[name] {
			t.Fatalf("expected a successful source named %q, none found in %+v", name, loc.Sources)
		}
	}
}

func TestLocateNilClientReturnsError(t *testing.T) {
	srcs := []source{
		{Name: "ip.pn", URL: "http://127.0.0.1:0/json", Parse: parseIpPn},
	}
	loc, err := locate(context.Background(), nil, srcs, LocateOptions{})
	if err != ErrNilClient {
		t.Fatalf("err = %v, want ErrNilClient", err)
	}
	if loc != nil {
		t.Fatalf("expected nil result on nil client, got %+v", loc)
	}
}

func TestLocateQuorumFail(t *testing.T) {
	ok := jsonServer(`{"status":"success","countryCode":"US","country":"United States"}`)
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	srcs := []source{
		{Name: "ip.pn", URL: ok.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: bad.URL, Parse: parseFreeIpApi},
		{Name: "ipinfo", URL: bad.URL, Parse: parseIpInfo},
	}
	if _, err := locate(context.Background(), &http.Client{}, srcs, LocateOptions{}); err != ErrNoConsensus {
		t.Fatalf("err = %v, want ErrNoConsensus", err)
	}
}

func TestLocateTimeoutCountsAsFailure(t *testing.T) {
	old := PerSourceTimeout
	PerSourceTimeout = 100 * time.Millisecond
	defer func() { PerSourceTimeout = old }()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"country":"US"}`))
	}))
	defer slow.Close()
	good := jsonServer(`{"status":"success","countryCode":"US","country":"United States"}`)
	defer good.Close()

	// two good, one slow -> still quorum; slow one recorded as a failure.
	srcs := []source{
		{Name: "ip.pn", URL: good.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: good.URL, Parse: parseIpPn},
		{Name: "ipinfo", URL: slow.URL, Parse: parseIpInfo},
	}
	loc, err := locate(context.Background(), &http.Client{}, srcs, LocateOptions{})
	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	var slowRec *SourceResult
	for i := range loc.Sources {
		if loc.Sources[i].Name == "ipinfo" {
			slowRec = &loc.Sources[i]
		}
	}
	if slowRec == nil || slowRec.OK {
		t.Fatal("slow source should be recorded as a failure")
	}
	if slowRec.Err == "" {
		t.Fatal("slow source should carry an error string")
	}
}

// TestLocateRunsSourcesConcurrently guards the fan-out: locate() must bound
// its total latency by the slowest single source, not the sum of all
// sources. Each of the 3 sources sleeps sleepPerSource before responding
// with a valid, mutually-agreeing payload. If locate() ever regresses to
// fetching sources sequentially, the elapsed wall-clock roughly triples and
// trips the concurrentBound assertion below.
func TestLocateRunsSourcesConcurrently(t *testing.T) {
	old := PerSourceTimeout
	PerSourceTimeout = 2 * time.Second
	defer func() { PerSourceTimeout = old }()

	const sleepPerSource = 200 * time.Millisecond
	// Comfortably above one sleep (concurrent) and comfortably below three
	// sleeps (sequential), so this fails decisively if the fan-out is
	// serialized while staying robust to a loaded CI machine.
	const concurrentBound = 450 * time.Millisecond

	slowJSONServer := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(sleepPerSource)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}

	s1 := slowJSONServer(`{"status":"success","countryCode":"US","country":"United States","city":"Fairfax","asn":401486}`)
	s2 := slowJSONServer(`{"countryCode":"US","countryName":"United States","cityName":"Fairfax","regionName":"Virginia","asn":"401486"}`)
	s3 := slowJSONServer(`{"country":"US","city":"Fairfax","region":"Virginia","org":"AS401486 RAVNIX LLC"}`)
	// Servers sleep before every response, so Close() would block on any
	// still-in-flight handler; deferring Close outside the timed region
	// avoids polluting the elapsed measurement (Close is still called at
	// the end of the test, after locate() has returned).
	defer s1.Close()
	defer s2.Close()
	defer s3.Close()

	srcs := []source{
		{Name: "ip.pn", URL: s1.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: s2.URL, Parse: parseFreeIpApi},
		{Name: "ipinfo", URL: s3.URL, Parse: parseIpInfo},
	}

	start := time.Now()
	loc, err := locate(context.Background(), &http.Client{}, srcs, LocateOptions{})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	if !loc.CountryConfident || loc.CountryCode != "us" {
		t.Fatalf("country = %q confident=%v", loc.CountryCode, loc.CountryConfident)
	}
	okCount := 0
	for _, s := range loc.Sources {
		if s.OK {
			okCount++
		}
	}
	if okCount != 3 {
		t.Fatalf("expected all 3 sources to succeed, got %d: %+v", okCount, loc.Sources)
	}

	if elapsed >= concurrentBound {
		t.Fatalf("locate() took %v, want < %v; sources appear to be fetched sequentially instead of concurrently", elapsed, concurrentBound)
	}
}

func TestLocateOversizedResponseRejected(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{" + strings.Repeat(" ", MaxResponseBytes+10) + "}"))
	}))
	defer big.Close()
	good := jsonServer(`{"status":"success","countryCode":"US","country":"United States"}`)
	defer good.Close()

	srcs := []source{
		{Name: "ip.pn", URL: good.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: good.URL, Parse: parseIpPn},
		{Name: "ipinfo", URL: big.URL, Parse: parseIpInfo},
	}
	loc, err := locate(context.Background(), &http.Client{}, srcs, LocateOptions{})
	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	for _, s := range loc.Sources {
		if s.Name == "ipinfo" && (s.OK || !strings.Contains(s.Err, "too large")) {
			t.Fatalf("oversized source not rejected: %+v", s)
		}
	}
}

// TestLocatePerSourceTimeoutFromOptions is the regression test for the inert
// -probe-timeout: every source fetch used to be capped at the PerSourceTimeout
// package var, which the CLI never set, so the operator's only latency knob
// could not move the deadline that matters. LocateOptions.PerSourceTimeout
// must override the package default in BOTH directions -- raising it (the
// case that motivated the fix: a cold tunnel needs more than 5s) and lowering
// it -- and the zero value must still fall back to the package default so
// Locate's behavior is unchanged.
func TestLocatePerSourceTimeoutFromOptions(t *testing.T) {
	const serverDelay = 300 * time.Millisecond

	slowJSONServer := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(serverDelay)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}

	newSources := func(t *testing.T) []source {
		s1 := slowJSONServer(`{"status":"success","countryCode":"US","country":"United States"}`)
		s2 := slowJSONServer(`{"countryCode":"US","countryName":"United States"}`)
		s3 := slowJSONServer(`{"country":"US"}`)
		t.Cleanup(func() {
			s1.Close()
			s2.Close()
			s3.Close()
		})
		return []source{
			{Name: "ip.pn", URL: s1.URL, Parse: parseIpPn},
			{Name: "freeipapi", URL: s2.URL, Parse: parseFreeIpApi},
			{Name: "ipinfo", URL: s3.URL, Parse: parseIpInfo},
		}
	}

	okCount := func(loc *ConsensusLocation) int {
		n := 0
		for _, s := range loc.Sources {
			if s.OK {
				n++
			}
		}
		return n
	}

	// The option must be able to RAISE the bound above the package default:
	// this is the shape of the real defect, where -probe-timeout 60s was
	// silently clamped to 5s on a cold tunnel.
	t.Run("option raises the bound above the package default", func(t *testing.T) {
		old := PerSourceTimeout
		PerSourceTimeout = 50 * time.Millisecond // far too short for the servers below
		defer func() { PerSourceTimeout = old }()

		loc, err := locate(context.Background(), &http.Client{}, newSources(t), LocateOptions{
			PerSourceTimeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("locate err = %v; the configured 5s per-source timeout was not honored (the 50ms package default was still in force)", err)
		}
		if n := okCount(loc); n != 3 {
			t.Fatalf("%d/3 sources succeeded; the configured per-source timeout was not honored", n)
		}
	})

	// ...and to LOWER it, proving the value is genuinely threaded through to
	// each fetch rather than the package default happening to be permissive.
	t.Run("option lowers the bound below the package default", func(t *testing.T) {
		old := PerSourceTimeout
		PerSourceTimeout = 10 * time.Second
		defer func() { PerSourceTimeout = old }()

		start := time.Now()
		_, err := locate(context.Background(), &http.Client{}, newSources(t), LocateOptions{
			PerSourceTimeout: 30 * time.Millisecond,
		})
		elapsed := time.Since(start)
		if err != ErrNoConsensus {
			t.Fatalf("err = %v, want ErrNoConsensus: every source should have exceeded the 30ms per-source timeout", err)
		}
		if elapsed >= serverDelay {
			t.Fatalf("locate took %v, want well under the %v server delay: the 30ms per-source timeout did not cut the fetches short", elapsed, serverDelay)
		}
	})

	// The zero value must change nothing, so Locate keeps its documented
	// behavior for callers that do not opt in.
	t.Run("zero option falls back to the package default", func(t *testing.T) {
		old := PerSourceTimeout
		PerSourceTimeout = 30 * time.Millisecond
		defer func() { PerSourceTimeout = old }()

		if _, err := locate(context.Background(), &http.Client{}, newSources(t), LocateOptions{}); err != ErrNoConsensus {
			t.Fatalf("err = %v, want ErrNoConsensus: a zero LocateOptions must use the 30ms package default", err)
		}
	})
}
