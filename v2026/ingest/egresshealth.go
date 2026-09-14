package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
)

// egressHealthClassBody is one class's ok/total tally over the destinations
// this run SAMPLED.
type egressHealthClassBody struct {
	OK    int `json:"ok"`
	Total int `json:"total"`
}

// submitEgressHealthBody is the fixed contract of the server's
// handlers.SubmitProviderEgressHealthArgs
// (POST /network/provider-egress-health, X-UR-Operator-Secret header).
//
// The server rejects unknown fields, so this struct's json tags are not a
// convention here -- they are the wire format, and a rename on either side
// makes every submission 400. There is deliberately no measured_at: the server
// stamps arrival time, so a skewed prober clock cannot write a row that looks
// stale or future-dated.
type submitEgressHealthBody struct {
	ClientId string `json:"client_id"`
	// OKCount/TotalCount cover the SCORED classes only, over this run's
	// sample. The server checks that ClassResults sums to exactly these two.
	OKCount      int                              `json:"ok_count"`
	TotalCount   int                              `json:"total_count"`
	ClassResults map[string]egressHealthClassBody `json:"class_results"`
	// ReputationOK/ReputationTotal ride ALONGSIDE the health figures and are
	// never part of them. Result.OKCount/Result.Total already exclude the
	// reputation class (see egresshealth.ClassReputation), and the server
	// rejects a "reputation" key inside class_results outright, so there is no
	// path by which these two can end up inside the score. Keep it that way.
	ReputationOK          int    `json:"reputation_ok"`
	ReputationTotal       int    `json:"reputation_total"`
	FailedNames           string `json:"failed_names"`
	ReputationFailedNames string `json:"reputation_failed_names"`
	// TLSAuthenticationFailure is deliberately outside all score fields. One
	// unauthenticated destination is a hard provider failure even when the
	// remaining sampled destinations make the percentage look healthy.
	TLSAuthenticationFailure bool `json:"tls_authentication_failure"`
}

// SubmitEgressHealth records one egress-health run for one provider.
//
// Until this existed the run was a log line and nothing else, so the one
// signal that says whether a provider carries traffic at all rolled off with
// the container logs.
//
// A server with no health endpoint (404) answers egresshealth.ErrUnsupported,
// which is a clean skip rather than a failure: the prober keeps working
// against a deployment that has not shipped this endpoint yet, it just records
// no health. This mirrors the bandwidth path exactly.
//
// The two reputation figures are sent because they were measured in the same
// pass, and they are sent SEPARATELY from ok/total because reputation is not
// health -- it measures whether large vendors treat the exit as a datacenter
// address, which nearly every honest hosted provider fails. The same applies
// to the two failure name lists, which stay apart for the same reason:
// "failed" names destinations the provider did not carry, "reputation-failed"
// names vendors that refused a datacenter ip.
func (c *Client) SubmitEgressHealth(
	ctx context.Context,
	providerClientId string,
	res *egresshealth.Result,
) error {
	if res == nil {
		// nothing measured. Submitting a zero here would be indistinguishable
		// from a total blackhole, which is a false accusation against a
		// provider whose check simply did not run.
		return nil
	}

	classResults := map[string]egressHealthClassBody{}
	for class, summary := range res.ByClass {
		// ByClass carries the scored classes only -- egresshealth keeps
		// ClassReputation out of it -- so nothing filters here. If that ever
		// changes, the server 400s rather than quietly scoring reputation.
		classResults[string(class)] = egressHealthClassBody{OK: summary.OK, Total: summary.Total}
	}

	buf, err := json.Marshal(submitEgressHealthBody{
		ClientId:                 providerClientId,
		OKCount:                  res.OKCount,
		TotalCount:               res.Total,
		ClassResults:             classResults,
		ReputationOK:             res.Reputation.OK,
		ReputationTotal:          res.Reputation.Total,
		TLSAuthenticationFailure: res.TLSAuthenticationFailure,
		// Bounded like probe_failure, and for the same reason: a run with
		// many failures names ~131 destinations under -egress-health-all, and
		// a submission the server rejects for length is a health signal
		// dropped silently, since the prober submits these fire-and-forget
		// with deduplicated error logging. Cut on element boundaries with a
		// dropped count -- see truncateNameList and MaxNameListLen.
		FailedNames:           truncateNameList(res.FailedNames(), MaxNameListLen),
		ReputationFailedNames: truncateNameList(res.ReputationFailedNames(), MaxNameListLen),
	})
	if err != nil {
		return err
	}

	url := strings.TrimRight(c.ServerURL, "/") + "/network/provider-egress-health"
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
		return egresshealth.ErrUnsupported
	case http.StatusUnauthorized:
		return ErrUnauthorized
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: status %d: %s", ErrRejected, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
}
