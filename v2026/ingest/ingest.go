// Package ingest submits probed provider locations to the operator's server.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/geolocate"
)

// ErrNotConfident is returned when a result is not country-confident. Such a
// result is never submitted: the server keeps its own fallback, which is better
// than recording a guess.
var ErrNotConfident = errors.New("ingest: result is not country-confident")

// ErrIncompleteCountry is returned when a country-confident result does not
// carry a complete, usable country record: the code must be alpha-2 and the
// name must be non-empty, or the server rejects the POST outright ("Country
// code must be alpha-2." / "Missing country."). geolocate's consensus already
// degrades such a result to not-country-confident; this is the last gate
// before the wire, and it matters because the scheduler caches successes
// only -- a rejected submission is retried on every pass, forever, so a
// doomed POST is not a one-off cost. Failing locally turns that permanent
// loop into a clean skip.
var ErrIncompleteCountry = errors.New("ingest: country-confident result needs an alpha-2 code and a non-empty country name")

// ErrRejected is returned when the server rejects a submission.
var ErrRejected = errors.New("ingest: server rejected the submission")

// ErrMissingProbedAt is returned when loc.ProbedAt is zero. Submit never
// fabricates an "observed now" timestamp: doing so would defeat the
// server's age check and could permanently pin a stale or wrong location,
// since the server's monotonic upsert would then reject later genuine
// probes and its expiry sweep would never remove it.
var ErrMissingProbedAt = errors.New("ingest: loc.ProbedAt is zero")

// isAlpha2 reports whether code is exactly two ASCII letters, the shape the
// server requires of country_code.
func isAlpha2(code string) bool {
	if len(code) != 2 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c < 'a' || 'z' < c {
			if c < 'A' || 'Z' < c {
				return false
			}
		}
	}
	return true
}

// Client talks to the server's operator endpoints: it posts probed locations,
// reports probe attempts, and asks which providers are due. All three
// authenticate with the same X-UR-Operator-Secret header -- one secret, one
// mechanism, one thing for a deployment to get right.
type Client struct {
	ServerURL      string
	OperatorSecret string
	HTTP           *http.Client
	// DueURL overrides the due endpoint derived from ServerURL. Empty means
	// "<ServerURL>/network/provider-egress-due".
	DueURL string
	// ShardIndex/ShardCount select one slice of the due queue for this worker.
	//
	// The queue hands work out but does not claim it: the server's dedupe only
	// bites once an attempt row lands, which is at submit time, minutes after a
	// batch went out. So every worker polling inside that window receives the
	// same rows, and N workers repeat one slice's work instead of dividing it.
	// Sharding on the server's hash of client_id gives each task or standalone
	// prober a disjoint slice; scheduling and host ownership stay with callers.
	//
	// A zero ShardCount (or 1) is the single-prober case: the parameters are
	// omitted from the request entirely, so this is also safe against a server
	// that predates them.
	ShardIndex int
	ShardCount int
}

type submitBody struct {
	ClientId         string    `json:"client_id"`
	CountryCode      string    `json:"country_code"`
	Country          string    `json:"country"`
	Region           string    `json:"region,omitempty"`
	City             string    `json:"city,omitempty"`
	ASN              int       `json:"asn,omitempty"`
	Org              string    `json:"org,omitempty"`
	Hosting          bool      `json:"hosting,omitempty"`
	Proxy            bool      `json:"proxy,omitempty"`
	Mobile           bool      `json:"mobile,omitempty"`
	CountryConfident bool      `json:"country_confident"`
	CityConfident    bool      `json:"city_confident,omitempty"`
	ObservedAt       time.Time `json:"observed_at"`
}

// Submit posts one probed location. The body shape is the fixed contract of
// the server's controller.SubmitProviderEgressLocationArgs
// (POST /network/provider-egress-location, X-UR-Operator-Secret header).
//
// Submit refuses to contact the server at all when loc is not
// CountryConfident: the server prefers a stored submission over its own geo
// database, so a low-confidence guess must never be recorded. It likewise
// refuses a country-confident result whose country record is incomplete (see
// ErrIncompleteCountry), which the server would reject anyway.
func (c *Client) Submit(ctx context.Context, providerClientId string, loc *geolocate.ConsensusLocation) error {
	if loc == nil || !loc.CountryConfident {
		return ErrNotConfident
	}
	if loc.ProbedAt.IsZero() {
		return ErrMissingProbedAt
	}
	if !isAlpha2(loc.CountryCode) || strings.TrimSpace(loc.Country) == "" {
		return fmt.Errorf("%w: code=%q name=%q", ErrIncompleteCountry, loc.CountryCode, loc.Country)
	}
	body := submitBody{
		ClientId:         providerClientId,
		CountryCode:      loc.CountryCode,
		Country:          loc.Country,
		ASN:              loc.ASN,
		Org:              loc.Org,
		Hosting:          loc.Hosting,
		Proxy:            loc.Proxy,
		Mobile:           loc.Mobile,
		CountryConfident: true,
		CityConfident:    loc.CityConfident,
		ObservedAt:       loc.ProbedAt,
	}
	if loc.CityConfident {
		body.City = loc.City
		body.Region = loc.Region
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(c.ServerURL, "/") + "/network/provider-egress-location"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-UR-Operator-Secret", c.OperatorSecret)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 401 is mapped like every other method's, so a wrong -operator-secret
	// reaches the caller as ErrUnauthorized with its remediation advice. This
	// was the one method that did not: against a server without the due
	// endpoint the prober falls back to enumeration, which authenticates with
	// the byJwt rather than the operator secret, so the pass proceeds and a
	// wrong secret surfaced only as a per-provider "status 401" classified
	// submit_failed -- the quiet degradation ErrUnauthorized exists to
	// prevent.
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: %w", ErrRejected, ErrUnauthorized)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: status %d: %s", ErrRejected, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
