package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/geolocate"
)

// TestSubmitPostsContractShape locks down the wire shape of submitBody
// against the server's fixed contract (controller.SubmitProviderEgressLocationArgs).
// Every one of the 13 JSON fields is asserted both for presence/absence per
// its omitempty semantics and for a round-tripped, distinctive value, so a
// silent field rename or dropped assignment is caught here rather than as a
// server-side zero-value that fails with no error anywhere.
func TestSubmitPostsContractShape(t *testing.T) {
	var got map[string]any
	var gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"location_id":"019f0000-0000-0000-0000-000000000000"}`))
	}))
	defer srv.Close()

	probedAt := time.Date(2026, 7, 25, 12, 34, 56, 0, time.UTC)
	c := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode:      "us",
		Country:          "United States",
		CountryConfident: true,
		City:             "Fremont",
		Region:           "California",
		CityConfident:    true,
		ASN:              401486,
		Org:              "RAVNIX LLC",
		Hosting:          true,
		Proxy:            true,
		Mobile:           true,
		ProbedAt:         probedAt,
	})
	if err != nil {
		t.Fatalf("Submit err = %v", err)
	}
	if gotSecret != "s3cret" {
		t.Fatalf("operator secret header = %q", gotSecret)
	}

	// All 13 wire fields must be present (every field is non-zero in this input).
	for _, k := range []string{
		"client_id", "country_code", "country", "region", "city",
		"asn", "org", "hosting", "proxy", "mobile",
		"country_confident", "city_confident", "observed_at",
	} {
		if _, ok := got[k]; !ok {
			t.Fatalf("body missing %q: %v", k, got)
		}
	}

	// Every field's value must round-trip from the input ConsensusLocation.
	wantString := map[string]string{
		"client_id":    "019f8835-158d-6fd8-e9dd-fd0e4c6d6792",
		"country_code": "us",
		"country":      "United States",
		"region":       "California",
		"city":         "Fremont",
		"org":          "RAVNIX LLC",
	}
	for k, want := range wantString {
		if got[k] != want {
			t.Fatalf("%s = %v, want %q", k, got[k], want)
		}
	}
	if got["asn"] != float64(401486) {
		t.Fatalf("asn = %v, want %v", got["asn"], 401486)
	}
	wantBool := map[string]bool{
		"hosting":           true,
		"proxy":             true,
		"mobile":            true,
		"country_confident": true,
		"city_confident":    true,
	}
	for k, want := range wantBool {
		if got[k] != want {
			t.Fatalf("%s = %v, want %v", k, got[k], want)
		}
	}
	gotObservedAt, ok := got["observed_at"].(string)
	if !ok {
		t.Fatalf("observed_at = %v, want RFC3339 string", got["observed_at"])
	}
	parsed, err := time.Parse(time.RFC3339, gotObservedAt)
	if err != nil {
		t.Fatalf("observed_at = %q not parseable: %v", gotObservedAt, err)
	}
	if !parsed.Equal(probedAt) {
		t.Fatalf("observed_at = %v, want %v", parsed, probedAt)
	}
}

// TestSubmitOmitsCityAndFalseBooleansWhenNotSet covers the non-confident /
// zero-value shape: city, region and city_confident are only sent when
// CityConfident is true (the client's own rule), and the omitempty boolean
// and numeric fields are absent from the wire when false/zero.
func TestSubmitOmitsCityAndFalseBooleansWhenNotSet(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"location_id":"019f0000-0000-0000-0000-000000000000"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode:      "us",
		Country:          "United States",
		CountryConfident: true,
		CityConfident:    false,
		City:             "should-not-be-sent",
		Region:           "should-not-be-sent",
		ProbedAt:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Submit err = %v", err)
	}

	for _, k := range []string{"city", "region", "city_confident", "asn", "org", "hosting", "proxy", "mobile"} {
		if v, ok := got[k]; ok {
			t.Fatalf("body must omit %q when unset/false, got %v", k, v)
		}
	}
	// Required fields still present.
	for _, k := range []string{"client_id", "country_code", "country", "country_confident", "observed_at"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("body missing %q: %v", k, got)
		}
	}
}

func TestSubmitRefusesNotCountryConfident(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryConfident: false,
	})
	if err == nil {
		t.Fatal("a non-country-confident result must not be submitted")
	}
	if called {
		t.Fatal("must not reach the server at all")
	}
}

// TestSubmitRefusesMissingProbedAt covers FIX 2: Submit must not fabricate an
// "observed now" timestamp when loc.ProbedAt is zero. It must refuse before
// any network call, the same way TestSubmitRefusesNotCountryConfident does.
func TestSubmitRefusesMissingProbedAt(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode:      "us",
		Country:          "United States",
		CountryConfident: true,
		// ProbedAt intentionally left zero.
	})
	if err == nil {
		t.Fatal("a zero ProbedAt must not be submitted")
	}
	if called {
		t.Fatal("must not reach the server at all")
	}
}

func TestSubmitSurfacesRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unknown client.", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode: "us", Country: "United States", CountryConfident: true, ProbedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("a 400 must surface as an error")
	}
}

// TestSubmitMaps401ToErrUnauthorized: every other method on this client maps
// 401, and the CLI keys its remediation advice ("check -operator-secret
// against ingest_secret") off the sentinel. Submit was the one that did not,
// and the gap is reachable: against a server without the due endpoint the
// prober falls back to enumeration, which authenticates with the byJwt, so a
// wrong operator secret let the whole pass proceed and surfaced only as a
// per-provider "status 401" classified submit_failed.
func TestSubmitMaps401ToErrUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "wrong", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode: "us", Country: "United States", CountryConfident: true, ProbedAt: time.Now().UTC(),
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want it to wrap ErrUnauthorized", err)
	}
}

// TestSubmitRefusesIncompleteCountry is the last-gate half of the F2 fix.
// geolocate's consensus no longer produces these shapes, but Submit is the
// boundary that owns the wire contract, and the cost of letting one through
// is not a single failed POST: the scheduler caches successes only, so a
// server rejection ("Country code must be alpha-2." / "Missing country.")
// makes the provider re-probe and re-fail on every pass, forever. Both shapes
// must be refused locally, without touching the network.
func TestSubmitRefusesIncompleteCountry(t *testing.T) {
	cases := []struct {
		name string
		loc  *geolocate.ConsensusLocation
	}{
		{
			name: "empty country name",
			loc: &geolocate.ConsensusLocation{
				CountryCode:      "xk", // Kosovo: real, two characters, absent from ISO 3166-1
				CountryConfident: true,
				ProbedAt:         time.Now().UTC(),
			},
		},
		{
			name: "whitespace-only country name",
			loc: &geolocate.ConsensusLocation{
				CountryCode:      "us",
				Country:          "   ",
				CountryConfident: true,
				ProbedAt:         time.Now().UTC(),
			},
		},
		{
			name: "non alpha-2 country code",
			loc: &geolocate.ConsensusLocation{
				CountryCode:      "usa",
				Country:          "United States",
				CountryConfident: true,
				ProbedAt:         time.Now().UTC(),
			},
		},
		{
			name: "empty country code",
			loc: &geolocate.ConsensusLocation{
				CountryCode:      "",
				Country:          "United States",
				CountryConfident: true,
				ProbedAt:         time.Now().UTC(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))
			defer srv.Close()

			c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
			err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", tc.loc)
			if !errors.Is(err, ErrIncompleteCountry) {
				t.Fatalf("err = %v, want it to wrap ErrIncompleteCountry", err)
			}
			if called {
				t.Fatal("must not reach the server at all: a doomed POST here is retried on every pass forever")
			}
		})
	}
}
