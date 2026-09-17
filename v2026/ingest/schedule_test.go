package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestDueRequestsTheContract locks the due request against the server's fixed
// contract: GET /network/provider-egress-due?limit=N with the operator secret
// header, decoding {"client_ids":[...]}.
func TestDueRequestsTheContract(t *testing.T) {
	var gotPath, gotQuery, gotMethod, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		_, _ = w.Write([]byte(`{"client_ids":["019f8835-158d-6fd8-e9dd-fd0e4c6d6792","019f8835-158d-6fd8-e9dd-fd0e4c6d6793"]}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	ids, err := c.Due(context.Background(), 250)
	if err != nil {
		t.Fatalf("Due err = %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotPath != "/network/provider-egress-due" {
		t.Errorf("path = %q, want /network/provider-egress-due", gotPath)
	}
	if gotQuery != "limit=250" {
		t.Errorf("query = %q, want limit=250", gotQuery)
	}
	// the same secret mechanism the submit path already uses; a second one
	// would be a second thing to get wrong in a deployment
	if gotSecret != "s3cret" {
		t.Errorf("operator secret header = %q", gotSecret)
	}
	if len(ids) != 2 || ids[0] != "019f8835-158d-6fd8-e9dd-fd0e4c6d6792" {
		t.Fatalf("Due = %v", ids)
	}
}

// TestDueHonoursDueURL: the operator can point the prober at a different due
// endpoint than the one derived from -api-url.
func TestDueHonoursDueURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"client_ids":[]}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: "http://unused.invalid", DueURL: srv.URL + "/elsewhere/due", OperatorSecret: "s", HTTP: srv.Client()}
	if _, err := c.Due(context.Background(), 10); err != nil {
		t.Fatalf("Due err = %v", err)
	}
	if gotPath != "/elsewhere/due" {
		t.Fatalf("path = %q, want the configured DueURL to win over ServerURL", gotPath)
	}
}

// TestDueReportsUnsupportedOn404 is what makes the prober work against a
// server that has not deployed the endpoint yet: 404 must be distinguishable
// so the caller can fall back to enumeration.
func TestDueReportsUnsupportedOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	_, err := c.Due(context.Background(), 10)
	if !errors.Is(err, ErrDueUnsupported) {
		t.Fatalf("Due err = %v, want ErrDueUnsupported so the caller can fall back to enumeration", err)
	}
}

// TestDueDoesNotReportUnsupportedOn401: a 401 is a wrong operator secret, not
// an old server. Folding it into the fallback would silently downgrade a
// misconfigured deployment to enumeration and hide the real fault -- while
// every submission it then made would be rejected by the same bad secret.
func TestDueDoesNotReportUnsupportedOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "wrong", HTTP: srv.Client()}
	_, err := c.Due(context.Background(), 10)
	if err == nil {
		t.Fatal("Due accepted a 401")
	}
	if errors.Is(err, ErrDueUnsupported) {
		t.Fatalf("Due err = %v, must NOT be ErrDueUnsupported: a 401 is a misconfigured secret and must be loud, not a silent fallback", err)
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Due err = %v, want ErrUnauthorized", err)
	}
}

func TestDueRejectsOtherErrorStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	if _, err := c.Due(context.Background(), 10); !errors.Is(err, ErrRejected) {
		t.Fatalf("Due err = %v, want ErrRejected", err)
	}
}

// TestDueRejectsNonPositiveLimit: the server answers 400 to limit<1, because
// limit=0 comes back as an empty list that the prober cannot tell apart from
// "nothing is due". Catch it before the round trip.
func TestDueRejectsNonPositiveLimit(t *testing.T) {
	c := &Client{ServerURL: "http://unused.invalid", OperatorSecret: "s"}
	for _, limit := range []int{0, -1} {
		if _, err := c.Due(context.Background(), limit); err == nil {
			t.Fatalf("Due accepted limit=%d; an empty result is indistinguishable from \"nothing is due\"", limit)
		}
	}
}

// TestReportAttemptPostsTheContract locks the attempt request against
// controller.RecordProviderEgressProbeAttemptArgs.
func TestReportAttemptPostsTheContract(t *testing.T) {
	var got map[string]any
	var gotPath, gotMethod, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"attempt_at":"2026-07-26T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	if err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", "tunnel_failed"); err != nil {
		t.Fatalf("ReportAttempt err = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/network/provider-egress-attempt" {
		t.Errorf("path = %q, want /network/provider-egress-attempt", gotPath)
	}
	if gotSecret != "s3cret" {
		t.Errorf("operator secret header = %q", gotSecret)
	}
	if got["client_id"] != "019f8835-158d-6fd8-e9dd-fd0e4c6d6792" {
		t.Errorf("client_id = %v", got["client_id"])
	}
	if got["probe_failure"] != "tunnel_failed" {
		t.Errorf("probe_failure = %v, want tunnel_failed", got["probe_failure"])
	}
}

// TestReportAttemptOmitsProbeFailureOnSuccess: "" means success on the wire.
func TestReportAttemptOmitsProbeFailureOnSuccess(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"attempt_at":"2026-07-26T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	if err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", ""); err != nil {
		t.Fatalf("ReportAttempt err = %v", err)
	}
	if v, ok := got["probe_failure"]; ok && v != "" {
		t.Fatalf("probe_failure = %v, want it omitted or empty on success", v)
	}
}

// TestReportAttemptTruncatesProbeFailure: the server's column is varchar(64)
// and the controller rejects anything longer with a 400 -- which would turn a
// long failure class into a *lost attempt report*, i.e. straight back into the
// starvation this endpoint exists to fix.
func TestReportAttemptTruncatesProbeFailure(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"attempt_at":"2026-07-26T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	long := strings.Repeat("x", 200)
	if err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", long); err != nil {
		t.Fatalf("ReportAttempt err = %v", err)
	}
	sent, _ := got["probe_failure"].(string)
	if len(sent) != MaxProbeFailureLen {
		t.Fatalf("probe_failure length = %d, want it truncated to %d (the server's column width)", len(sent), MaxProbeFailureLen)
	}
}

// TestTruncateUTF8DoesNotSplitARune: every current caller passes ASCII, so a
// byte-boundary cut is invisible today and would corrupt the moment one does
// not -- json marshals a partial encoding as U+FFFD.
func TestTruncateUTF8DoesNotSplitARune(t *testing.T) {
	// "é" occupies bytes 1-2, so a cut at 2 lands inside it and must back up
	// to the boundary at 1; a cut at 3 is already on a boundary and stands.
	if got := truncateUTF8("aéb", 2); got != "a" {
		t.Fatalf("truncateUTF8(\"aéb\", 2) = %q, want \"a\": the cut must fall back to a rune boundary", got)
	}
	if got := truncateUTF8("aéb", 3); got != "aé" {
		t.Fatalf("truncateUTF8(\"aéb\", 3) = %q, want \"aé\": a cut already on a boundary must not lose a rune", got)
	}
	if got := truncateUTF8("abc", 10); got != "abc" {
		t.Fatalf("truncateUTF8 shortened a string already within the limit: %q", got)
	}
	if !utf8.ValidString(truncateUTF8(strings.Repeat("é", 40), 61)) {
		t.Fatal("truncateUTF8 produced invalid utf-8")
	}
}

func TestReportAttemptSurfacesUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "wrong", HTTP: srv.Client()}
	err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", "tunnel_failed")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ReportAttempt err = %v, want ErrUnauthorized", err)
	}
}

// TestReportAttemptTolerates404: an old server has no attempt endpoint. The
// prober must keep probing against it, so this is reported as unsupported
// rather than as a probe failure.
func TestReportAttemptTolerates404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", "tunnel_failed")
	if !errors.Is(err, ErrAttemptUnsupported) {
		t.Fatalf("ReportAttempt err = %v, want ErrAttemptUnsupported", err)
	}
}

// TestTruncateNameListCutsOnElementBoundaries: cutting mid-element invents a
// destination. Review measured a real case -- a 1388-byte, 131-name list cut
// at 512 bytes ended in "kernel-org-mirror" while the real destination is
// "kernel-org-mirrors" -- which is indistinguishable from a genuine name, so
// a query for providers failing it silently returns nothing.
func TestTruncateNameListCutsOnElementBoundaries(t *testing.T) {
	names := []string{"kernel-org-mirrors", "cachefly", "akamai", "etsy", "canva"}
	got := truncateNameList(names, 30)

	if len(got) > 30 {
		t.Fatalf("truncateNameList = %q (%d bytes), want at most 30", got, len(got))
	}
	// Every name before the marker must be a whole name from the input.
	listed, _, _ := strings.Cut(got, "…")
	for _, name := range strings.Split(listed, ",") {
		if name == "" {
			continue
		}
		if !slices.Contains(names, name) {
			t.Errorf("truncateNameList emitted %q, which is not one of the real destinations: a partial name reads as a genuine one", name)
		}
	}
	if !strings.Contains(got, "more") {
		t.Errorf("truncateNameList = %q, want a dropped-count marker so a truncated list is distinguishable from a short one", got)
	}
	// A list inside the budget is returned untouched, with no marker.
	if got := truncateNameList(names[:2], 512); got != "kernel-org-mirrors,cachefly" {
		t.Errorf("truncateNameList within budget = %q, want the plain join", got)
	}
	if got := truncateNameList(nil, 512); got != "" {
		t.Errorf("truncateNameList(nil) = %q, want empty", got)
	}
	// A single name wider than the whole budget still cannot overflow it.
	if got := truncateNameList([]string{strings.Repeat("x", 400)}, 40); len(got) > 40 {
		t.Errorf("truncateNameList = %q (%d bytes), want at most 40", got, len(got))
	}
}

// A single-prober client must not send the shard parameters at all. That is
// what keeps this prober working against a server that predates them, and it
// means an unsharded deployment issues the identical request it always did.
func TestDueOmitsShardParamsWhenUnsharded(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"client_ids":[]}`))
	}))
	defer srv.Close()

	for _, count := range []int{0, 1} {
		c := &Client{ServerURL: srv.URL, OperatorSecret: "s", ShardCount: count}
		if _, err := c.Due(context.Background(), 10); err != nil {
			t.Fatalf("shard count %d: %v", count, err)
		}
		if strings.Contains(gotQuery, "shard_") {
			t.Fatalf("shard count %d: sent shard params when unsharded: %q", count, gotQuery)
		}
	}
}

// A sharded client sends both parameters, so the server hands it its own slice
// rather than the whole queue.
func TestDueSendsShardParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"client_ids":[]}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", ShardIndex: 4, ShardCount: 6}
	if _, err := c.Due(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shard_count=6", "shard_index=4"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

// An out-of-range shard is rejected before the request is issued. The server
// would answer 400, but a prober that silently probed nothing on every pass
// would look exactly like a fleet that was already fully probed.
func TestDueRejectsOutOfRangeShard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Due should not have issued a request for an out-of-range shard")
	}))
	defer srv.Close()

	for _, tc := range []struct{ index, count int }{{6, 6}, {-1, 6}, {9, 6}} {
		c := &Client{ServerURL: srv.URL, OperatorSecret: "s", ShardIndex: tc.index, ShardCount: tc.count}
		if _, err := c.Due(context.Background(), 10); err == nil {
			t.Fatalf("index %d of %d: expected an error", tc.index, tc.count)
		}
	}
}
