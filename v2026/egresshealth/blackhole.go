package egresshealth

import (
	"context"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
)

// BlackholeSampleSize is how many destinations one blackhole check asks for.
//
// Three, not one: a single destination conflates "this provider carries no
// traffic" with "this destination is having a bad minute", and the check's
// whole job is to be trusted enough to remove a provider from the public list.
// Three drawn from different operators makes a false positive require three
// independent failures at once.
//
// Not more than three, because this runs hourly against the entire fleet and
// every added destination multiplies by the population. The rich picture is
// what Check is for; this answers one bit.
const BlackholeSampleSize = 3

// BlackholeResult is the outcome of one provider's check.
type BlackholeResult struct {
	// OK is true when at least one destination answered correctly and NONE
	// failed TLS authentication. Ordinary partial reachability is degradation,
	// not a blackhole. A forged certificate is different: accepting the provider
	// after one unrelated endpoint succeeded would knowingly expose clients to
	// an unauthenticated peer.
	OK bool
	// Failure is "" when OK, otherwise a short class suitable for the server's
	// varchar(64): all_destinations_failed.
	Failure string
	// Results is every destination tried, for logging. A caller that reports
	// only the bit throws away the reason.
	Results []CheckResult
}

const (
	// FailureAllDestinationsFailed means none of the sampled destinations met
	// its content/status contract.
	FailureAllDestinationsFailed = "all_destinations_failed"
	// FailureTLSAuthentication means a sampled HTTPS peer could not authenticate
	// the requested host. It is a hard integrity failure even when a different
	// destination worked.
	FailureTLSAuthentication = "tls_authentication_failed"
)

// Blackhole answers one question about a provider: did ANY traffic get through.
//
// It exists beside Check rather than inside it because they answer different
// questions on different cadences. Check samples ~131 destinations across four
// classes to describe HOW a provider is failing, and is expensive enough that
// sweeping a fleet with it takes hours to days. In that window a provider that
// silently stops forwarding keeps its last passing measurement, and every
// consumer of that measurement keeps believing it -- while the provider stays
// connected and goes on accepting clients, because nothing about being dark
// looks different from the outside.
//
// So this is deliberately the cheapest useful check: a small fixed sample, one
// round trip each. The sample runs concurrently so checking every TLS identity
// consumes one request deadline rather than multiplying it by the sample size.
// It reuses fetch, and therefore the table's headers, body caps and Verify
// contracts -- a captive portal that answers 200 with its own body fails here
// exactly as it fails a full run, which is the property that makes "something
// got through" mean anything.
//
// Only the connectivity class is drawn. Those destinations exist to answer
// "is there internet", they are operated by several independent parties, they
// return a few hundred bytes at most, and they are the least likely in the
// table to be blocked for a reason that has nothing to do with the provider.
func Blackhole(ctx context.Context, client *http.Client, opts Options) *BlackholeResult {
	return blackhole(ctx, client, Destinations(), opts)
}

// blackhole is the testable form: the destination table is injected.
func blackhole(ctx context.Context, client *http.Client, dests []Destination, opts Options) *BlackholeResult {
	timeout := opts.PerRequestTimeout
	if timeout <= 0 {
		timeout = DefaultPerRequestTimeout
	}

	sample := blackholeSample(dests, opts.rng())

	result := &BlackholeResult{Failure: FailureAllDestinationsFailed}
	results := make([]CheckResult, len(sample))
	var wg sync.WaitGroup
	for i, d := range sample {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = fetch(ctx, client, d, timeout)
		}()
	}
	wg.Wait()
	result.Results = results

	sawSuccess := false
	for _, cr := range results {
		if cr.TLSAuthenticationFailure {
			result.Failure = FailureTLSAuthentication
			return result
		}
		if cr.OK {
			sawSuccess = true
		}
	}
	if sawSuccess {
		result.OK = true
		result.Failure = ""
	}

	return result
}

// blackholeSample draws up to BlackholeSampleSize connectivity destinations.
//
// Drawn fresh per run rather than fixed, for the same anti-gaming reason the
// full check samples: a provider that knew the three addresses could carry
// those and blackhole everything else.
func blackholeSample(dests []Destination, r *rand.Rand) []Destination {
	candidates := []Destination{}
	for _, d := range dests {
		if d.Class == ClassConnectivity {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	r.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	return candidates[:min(BlackholeSampleSize, len(candidates))]
}

// BlackholeHosts is the closed allowlist passed to the provider-tunnel client.
// The standalone command also uses it for its defense-in-depth confinement
// check. fleetprobe has no direct dialer to these hosts, so the taskworker's
// ordinary LAN route cannot satisfy a check when the provider tunnel is dark.
func BlackholeHosts() []string {
	seen := map[string]bool{}
	hosts := []string{}
	for _, d := range Destinations() {
		if d.Class != ClassConnectivity {
			continue
		}
		u, err := url.Parse(d.URL)
		if err != nil {
			continue
		}
		h := u.Hostname()
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}
