package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrPinsUnavailable reports that the server did not answer the pin endpoint
// with a usable set.
//
// There is deliberately no "the server does not implement this endpoint" error
// beside it, unlike ErrDueUnsupported and ErrAttemptUnsupported above. Those
// two exist so the prober keeps working against an older server by doing its
// own scheduling; the equivalent here would be to keep probing without the
// pins, and that is precisely the thing that must never happen. The geolocation
// lookup is issued THROUGH the provider under test, so the pin is the only
// thing stopping that provider substituting a certificate and forging its own
// apparent location. A prober that degraded to unpinned would go on producing
// location data that looks fine and is worthless -- which is strictly worse
// than one that stops, and is the same shape as the outage this mechanism
// exists to prevent (a pinned source failing closed merely shrank the source
// set and raised nothing).
//
// So a 404 here is an error like any other status. It is worth distinguishing
// in the MESSAGE -- "this server has not deployed the endpoint" is a different
// thing for an operator to fix than "the endpoint returned 500" -- but not in
// the control flow, because there is no behaviour to branch to.
var ErrPinsUnavailable = errors.New("ingest: could not get the geolocation certificate pins from the server")

// GeolocationPin is one host's observed certificate pin as the server serves
// it: the base64 sha-256 SPKI hash of the leaf certificate and of its issuing
// intermediate, both observed by the server on a DIRECT, WebPKI-validated
// connection with no provider in the path.
type GeolocationPin struct {
	Leaf         string `json:"leaf"`
	Intermediate string `json:"intermediate"`
}

// GeolocationPins fetches the certificate pins the server observed for the
// geolocation source hosts.
//
// The response is a bare object keyed by host,
// `{"ipinfo.io": {"leaf": "...", "intermediate": "..."}}`. It carries exactly
// what the server observed: a source host it has never successfully observed
// is ABSENT, not present-and-empty. That distinction is load-bearing and is
// preserved here rather than smoothed over -- the caller's correct response to
// a missing source host is to refuse to probe it, and it can only make that
// call if the gap survives this far.
//
// Every non-200 is an error, including 404. See ErrPinsUnavailable.
func (c *Client) GeolocationPins(ctx context.Context) (map[string]GeolocationPin, error) {
	url := strings.TrimRight(c.ServerURL, "/") + "/network/geolocation-source-pins"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-UR-Operator-Secret", c.OperatorSecret)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		// %w, not %s: a caller triaging a startup or shutdown needs
		// errors.Is(err, context.Canceled / DeadlineExceeded) to survive this
		// wrapping, the same way the 401 case below preserves its sentinel.
		return nil, fmt.Errorf("%w: %w", ErrPinsUnavailable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: %w", ErrPinsUnavailable, ErrUnauthorized)
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: status 404: this server has not deployed /network/geolocation-source-pins; upgrade it -- the prober will not probe unpinned", ErrPinsUnavailable)
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: status %d: %s", ErrPinsUnavailable, resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var pins map[string]GeolocationPin
	if err := json.NewDecoder(resp.Body).Decode(&pins); err != nil {
		return nil, fmt.Errorf("%w: decoding the response: %s", ErrPinsUnavailable, err)
	}
	// A body of `null` decodes into a nil map without error, which would
	// otherwise reach the caller looking like a successful fetch of an empty
	// set. Both are refused upstream (an empty set covers no source host), but
	// returning nil,nil here would make that refusal depend on the caller
	// rather than on this function.
	if pins == nil {
		return nil, fmt.Errorf("%w: the server sent no pin object", ErrPinsUnavailable)
	}
	return pins, nil
}
