package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
)

// ingestHealthResult is a provider whose tunnel works, which two CDNs refuse,
// and which two reputation vendors treat as a datacenter -- the ordinary shape
// of a hosted provider. OKCount/Total cover the scored classes only (9/11) and
// the reputation tally (1/3) sits outside them; folding it in would read 10/14.
func ingestHealthResult() *egresshealth.Result {
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

// TestSubmitEgressHealthSendsAWellFormedBody pins the wire contract against
// the server's handlers.SubmitProviderEgressHealthArgs.
//
// The server rejects unknown fields and requires class_results to sum to
// EXACTLY ok_count/total_count, so a field-name drift on either side turns
// every submission into a 400 -- and because the prober submits
// fire-and-forget with dedup-logged errors, the visible symptom is one log
// line followed by permanent silence while nothing is stored. Hence the
// assertion on the fully decoded body rather than on a couple of fields.
func TestSubmitEgressHealthSendsAWellFormedBody(t *testing.T) {
	var gotMethod, gotPath, gotSecret, gotContentType string
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		gotContentType = r.Header.Get("Content-Type")
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	if err := client.SubmitEgressHealth(context.Background(), "provider-1", ingestHealthResult()); err != nil {
		t.Fatalf("SubmitEgressHealth: %s", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/network/provider-egress-health" {
		t.Errorf("path = %s, want /network/provider-egress-health", gotPath)
	}
	if gotSecret != "s3cret" {
		t.Errorf("operator secret header = %q", gotSecret)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q", gotContentType)
	}

	var got submitEgressHealthBody
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal body: %s (raw = %s)", err, raw)
	}
	want := submitEgressHealthBody{
		ClientId:   "provider-1",
		OKCount:    9,
		TotalCount: 11,
		ClassResults: map[string]egressHealthClassBody{
			"dns":          {OK: 3, Total: 3},
			"connectivity": {OK: 2, Total: 2},
			"cdn":          {OK: 1, Total: 3},
			"site":         {OK: 3, Total: 3},
		},
		ReputationOK:    1,
		ReputationTotal: 3,
		// the two failure lists stay apart: the first names destinations the
		// provider did not carry, the second names vendors that refused a
		// datacenter ip, which is not a fault
		FailedNames:           "jsdelivr-fastly-mirror,amazon-cloudfront",
		ReputationFailedNames: "akamai,etsy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body =\n%+v\nwant\n%+v", got, want)
	}

	// the server rejects unknown fields, so the wire form must carry exactly
	// the keys it declares -- decode into a bare map to catch an extra one that
	// the typed decode above would silently ignore
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal body as a map: %s", err)
	}
	wantKeys := map[string]bool{
		"client_id": true, "ok_count": true, "total_count": true,
		"class_results": true, "reputation_ok": true, "reputation_total": true,
		"failed_names": true, "reputation_failed_names": true,
		"tls_authentication_failure": true,
	}
	for k := range keys {
		if !wantKeys[k] {
			t.Errorf("body carries %q, which the server does not declare and will reject", k)
		}
	}
	for k := range wantKeys {
		if _, present := keys[k]; !present {
			t.Errorf("body is missing %q", k)
		}
	}
}

// A TLS identity failure is a hard signal, not one failed request diluted into
// ok_count/total_count. Pin the wire field that lets the server enforce that
// distinction independently of the broad health-score rollout switch.
func TestSubmitEgressHealthSendsTLSAuthenticationFailure(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := ingestHealthResult()
	result.TLSAuthenticationFailure = true
	client := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	if err := client.SubmitEgressHealth(context.Background(), "provider-1", result); err != nil {
		t.Fatalf("SubmitEgressHealth: %s", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal body: %s", err)
	}
	if value, ok := got["tls_authentication_failure"].(bool); !ok || !value {
		t.Fatalf("tls_authentication_failure = %#v, want true", got["tls_authentication_failure"])
	}
}

// TestSubmitEgressHealthNeverScoresReputation is the constraint the whole
// feature turns on. The reputation class measures whether large vendors treat
// the exit ip as a datacenter address; nearly every honest hosted provider
// fails most of it, because it IS hosted. This asserts the submitted health
// figures are 9/11 (the scored classes) and not 10/14, and that no class named
// "reputation" appears in class_results -- which the server rejects outright.
func TestSubmitEgressHealthNeverScoresReputation(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	if err := client.SubmitEgressHealth(context.Background(), "provider-1", ingestHealthResult()); err != nil {
		t.Fatalf("SubmitEgressHealth: %s", err)
	}

	var got submitEgressHealthBody
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal body: %s", err)
	}
	if got.OKCount != 9 || got.TotalCount != 11 {
		t.Fatalf("ok/total = %d/%d, want the scored classes only (9/11); 10/14 is reputation folded in",
			got.OKCount, got.TotalCount)
	}
	if _, present := got.ClassResults["reputation"]; present {
		t.Fatal("reputation was submitted as a scored class; the server rejects that outright")
	}
	// the class map must decompose the score exactly, which is what the server
	// checks and what makes a smuggled-in class impossible to hide
	sumOK, sumTotal := 0, 0
	for _, c := range got.ClassResults {
		sumOK += c.OK
		sumTotal += c.Total
	}
	if sumOK != got.OKCount || sumTotal != got.TotalCount {
		t.Fatalf("class_results sum to %d/%d, want %d/%d", sumOK, sumTotal, got.OKCount, got.TotalCount)
	}
}

// TestSubmitEgressHealthMapsStatusToOutcome pins the status contract. The 404
// case is the one that matters: a server that has not shipped the endpoint
// must be a clean skip (egresshealth.ErrUnsupported), not a failure, so a
// prober pointed at an older deployment keeps probing.
func TestSubmitEgressHealthMapsStatusToOutcome(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "stored", status: http.StatusOK, body: `{}`},
		{name: "server has no endpoint", status: http.StatusNotFound, wantErr: egresshealth.ErrUnsupported},
		{name: "wrong secret", status: http.StatusUnauthorized, wantErr: ErrUnauthorized},
		{name: "rejected payload", status: http.StatusBadRequest, body: "ok_count must not exceed total_count.", wantErr: ErrRejected},
		{name: "server error", status: http.StatusInternalServerError, body: "boom", wantErr: ErrRejected},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			client := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
			err := client.SubmitEgressHealth(context.Background(), "provider-1", ingestHealthResult())
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestSubmitEgressHealthIgnoresANilResult: the prober only submits after a run
// that produced a result, but a nil here must never become a submitted zero --
// that is indistinguishable from a total blackhole and would be a false
// accusation against a provider whose check simply did not run.
func TestSubmitEgressHealthIgnoresANilResult(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	if err := client.SubmitEgressHealth(context.Background(), "provider-1", nil); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if called {
		t.Fatal("a nil result was submitted as a zero score")
	}
}
