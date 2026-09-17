package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/operator-proxy/v2026/controlplane"
)

// ErrDueUnsupported reports that the server has no due endpoint (404). The
// caller falls back to enumerating providers itself, so the prober still works
// against a server that has not deployed it.
var ErrDueUnsupported = errors.New("ingest: the server does not implement /network/provider-egress-due")

// ErrAttemptUnsupported reports that the server has no attempt endpoint (404),
// for the same reason as ErrDueUnsupported. Probing continues; only the
// server-side backoff for failing providers is unavailable.
var ErrAttemptUnsupported = errors.New("ingest: the server does not implement /network/provider-egress-attempt")

// ErrUnauthorized reports that the server rejected the operator secret.
//
// This is deliberately NOT folded into ErrDueUnsupported. A 401 is a
// misconfigured deployment, not an old server: treating it as "fall back to
// enumeration" would hide the fault while every submission the prober went on
// to make was rejected by the same bad secret.
var ErrUnauthorized = errors.New("ingest: the server rejected the operator secret")

// MaxProbeFailureLen is the width of the server's probe_failure column
// (varchar(64)); controller.RecordProviderEgressProbeAttempt rejects anything
// longer with a 400. A rejected report is a LOST report, which puts the
// provider straight back at the head of the due queue -- the starvation the
// endpoint exists to prevent -- so a long class is truncated rather than sent.
const MaxProbeFailureLen = 64

// MaxNameListLen bounds each of the two failure-name lists in an
// egress-health submission. Unlike probe_failure the server's column width
// here is unconfirmed, so this is not a mirror of a known limit: it is the
// same defensive posture applied to the same kind of field. A heavy-failure
// run names ~26 destinations (400+ characters), and a submission rejected
// for length is a health signal silently dropped after one deduplicated log
// line, because the prober submits these fire-and-forget.
const MaxNameListLen = 512

// truncateUTF8 cuts s to at most max BYTES without splitting a rune.
// Truncating on a byte boundary can leave a partial encoding that json
// marshals as U+FFFD; every current caller passes ASCII, which is exactly
// why the failure would be silent when one eventually does not.
func truncateUTF8(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// truncateNameList cuts a comma-separated list to at most max bytes on an
// ELEMENT boundary, and appends a count of what it dropped.
//
// Cutting mid-element is worse than cutting fewer elements: a list ending
// "...,kernel-org-mirror" names a destination that does not exist, and is
// indistinguishable from one that does, so a query for providers failing that
// destination silently returns nothing. The dropped count matters for the
// same reason -- a blackholing provider under -egress-health-all names ~131
// destinations in ~1.4 KB, so most of the list is dropped, and a reader must
// be able to tell a short list from a truncated one.
func truncateNameList(names []string, max int) string {
	joined := strings.Join(names, ",")
	if len(joined) <= max {
		return joined
	}
	kept, used := 0, 0
	for _, name := range names {
		width := len(name)
		if 0 < kept {
			width++ // the separating comma
		}
		// Leave room for the "+N more" marker, which is what tells a reader
		// the list is partial.
		if max-len("…+999 more") < used+width {
			break
		}
		used += width
		kept++
	}
	if kept == 0 {
		// One name alone exceeds the budget: keep a rune-safe prefix rather
		// than nothing, and let the marker say the rest was dropped.
		return truncateUTF8(joined, max-len("…+999 more")) + fmt.Sprintf("…+%d more", len(names))
	}
	return strings.Join(names[:kept], ",") + fmt.Sprintf("…+%d more", len(names)-kept)
}

// dueURL resolves the due endpoint: the explicit DueURL when set, otherwise
// derived from ServerURL.
func (c *Client) dueURL() string {
	if c.DueURL != "" {
		return c.DueURL
	}
	return strings.TrimRight(c.ServerURL, "/") + "/network/provider-egress-due"
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTPClient
}

// One shared transport preserves connection pooling while making the default
// safe for every operator endpoint, including call sites that omit Client.HTTP.
var defaultHTTPClient = controlplane.NewHTTPClient(0)

// DueResult mirrors handlers.ProviderEgressLocationDueResult.
type dueResult struct {
	ClientIds []string `json:"client_ids"`
}

// Due asks the server which providers to probe next: those whose stored egress
// location has gone stale, those never probed, and those not attempted within
// the server's backoff, oldest first.
//
// This moves the probe schedule out of the prober's memory and into the
// database, where it survives a restart. limit must be positive: the server
// answers 400 to limit<1 precisely because an empty list is indistinguishable
// from "nothing is due", and it clamps the value to its own maximum.
//
// When ShardCount is above 1 the shard parameters are sent, so the server hands
// this worker only its own slice of the queue. Below that they are omitted
// entirely, which is both the single-prober case and what keeps this working
// against a server that predates them.
func (c *Client) Due(ctx context.Context, limit int) ([]string, error) {
	if limit < 1 {
		return nil, fmt.Errorf("ingest: due limit must be positive (got %d)", limit)
	}
	// Caught here rather than sent. The server answers 400, but an operator
	// reading an empty result as "nothing is due" is exactly the confusion the
	// limit<1 check above already exists to prevent.
	if 1 < c.ShardCount && (c.ShardIndex < 0 || c.ShardCount <= c.ShardIndex) {
		return nil, fmt.Errorf(
			"ingest: shard index %d is out of range for shard count %d",
			c.ShardIndex, c.ShardCount,
		)
	}

	u, err := url.Parse(c.dueURL())
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("limit", strconv.Itoa(limit))
	if 1 < c.ShardCount {
		q.Set("shard_count", strconv.Itoa(c.ShardCount))
		q.Set("shard_index", strconv.Itoa(c.ShardIndex))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-UR-Operator-Secret", c.OperatorSecret)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrDueUnsupported
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: status %d: %s", ErrRejected, resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var out dueResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.ClientIds, nil
}

type attemptBody struct {
	ClientId string `json:"client_id"`
	// ProbeFailure is omitted on success, otherwise a short failure class.
	ProbeFailure string `json:"probe_failure,omitempty"`
}

// ReportAttempt records that the prober tried this provider, whether or not the
// try produced a location. probeFailure is "" on success, otherwise a short
// class such as tunnel_failed, no_consensus or submit_failed.
//
// Every attempt must be reported, including successes. A provider that can
// never be probed successfully never gets a provider_egress_location row, so
// its observed_at stays NULL and the server's due query -- which sorts NULLs
// first -- hands it back on every poll, forever, starving every healthy
// provider. It fails silently, because the endpoint keeps returning a full and
// plausible batch. Reporting a success here is redundant (the location row
// defers the provider for far longer than the attempt backoff) but harmless,
// and reporting unconditionally means there is no path through the prober that
// forgets.
func (c *Client) ReportAttempt(ctx context.Context, providerClientId string, probeFailure string) error {
	probeFailure = truncateUTF8(probeFailure, MaxProbeFailureLen)

	buf, err := json.Marshal(attemptBody{ClientId: providerClientId, ProbeFailure: probeFailure})
	if err != nil {
		return err
	}

	url := strings.TrimRight(c.ServerURL, "/") + "/network/provider-egress-attempt"
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

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrAttemptUnsupported
	case http.StatusUnauthorized:
		return ErrUnauthorized
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: status %d: %s", ErrRejected, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
}
