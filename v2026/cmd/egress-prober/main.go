// Command egress-prober probes each provider's egress location by routing
// geolocation lookups through that provider, and submits the results to the
// operator's server. On the same tunnel it also runs an egress-health check
// (see egresshealth/) that measures whether the provider carries ordinary
// traffic at all, and logs a one-line per-provider summary. Health results are
// logged only -- nothing is submitted and there is no server endpoint for them
// yet.
//
// The same tunnel then carries an active bandwidth measurement (see
// bandwidth/) against two independent targets -- the operator's own download
// endpoint and a public CDN -- reported and stored separately, never averaged.
// Every provider is measured, not only those without passive history: the
// server's hourly byte budget is what regulates the spend, answering 429 once
// the current hour's bucket is full, so a full fleet is covered across
// successive hours rather than in one expensive pass.
//
// The prober host never contacts a geolocation api or a health destination
// directly: every request egresses through a provider tunnel. The only direct
// calls are to the operator's own server (provider list, ingest).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/urnetwork/connect/v2026"

	"github.com/urnetwork/operator-proxy/v2026/bandwidth"
	"github.com/urnetwork/operator-proxy/v2026/confinement"
	"github.com/urnetwork/operator-proxy/v2026/controlplane"
	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
	"github.com/urnetwork/operator-proxy/v2026/fleetprobe"
	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
	"github.com/urnetwork/operator-proxy/v2026/prober"
	"github.com/urnetwork/operator-proxy/v2026/providertunnel"
)

func main() {
	apiURL := flag.String("api-url", "", "operator server api url, e.g. https://api.example.net (required)")
	platformURL := flag.String("platform-url", "", "operator platform websocket url, e.g. wss://connect.example.net (required)")
	// The two secret flags MUST declare an empty default and read their env
	// var only after Parse (see envFallback below). Passing os.Getenv(...) as
	// the flag default instead makes flag.PrintDefaults render the live secret
	// as `(default "...")`, so every flag.Usage() call -- any missing required
	// flag, any parse error, and plain -h, which an operator runs routinely --
	// echoes both secrets verbatim to stderr, into journald or a CI log. That
	// would invert the README's own advice, which presents these env vars as
	// the way to keep secrets out of logs and ps.
	byJwt := flag.String("by-jwt", "", "the prober's network client jwt; prefer the UR_PROBER_BY_JWT env var, which keeps it out of ps. Leave it EMPTY to fetch it from the server's /network/prober-credential endpoint using -operator-secret, which is the unattended mode: the server mints the prober's identity in a bootstrap task and this waits for it. An explicitly supplied value always wins and is never overwritten")
	operatorSecret := flag.String("operator-secret", "", "ingest secret, must match ingest_secret in provider_egress.yml; prefer the UR_OPERATOR_SECRET env var, which keeps it out of ps (required)")
	concurrency := flag.Int("concurrency", 4, "max simultaneous provider tunnels")
	cacheTTL := flag.Duration("cache-ttl", 24*time.Hour, "do not re-probe a provider within this window. Only applies to the enumeration fallback used against a server with no due endpoint; when the server supplies the due list it owns the schedule")
	interval := flag.Duration("interval", time.Hour, "sleep AFTER a pass finishes, not a fixed period: the cycle is pass-duration + interval, so throughput is -due-limit / (pass-duration + interval) rather than -due-limit per interval. A 500-provider pass taking ~30m at -interval 1h yields ~390/hour with the prober idle two thirds of every cycle. Size it against how long a pass actually takes; 0 runs a single pass and exits")
	blackholeInterval := flag.Duration("blackhole-interval", time.Hour, "how often to sweep the WHOLE fleet with the cheap blackhole check (did any traffic get through). Separate from -interval on purpose: the full pass sweeps a fleet over hours to days, and a provider that goes dark keeps its last passing measurement for that whole window. 0 disables the sweep")
	blackholeLimit := flag.Int("blackhole-limit", 500, "providers per blackhole sweep request; the server clamps it to its own maximum")
	blackholeConcurrency := flag.Int("blackhole-concurrency", 32, "simultaneous blackhole checks. Higher than -concurrency because a check is one round trip through the tunnel rather than a ~131 destination sweep")
	blackholeTimeout := flag.Duration("blackhole-timeout", 15*time.Second, "per-request deadline for a blackhole check. Deliberately far shorter than -probe-timeout: this check asks one question and a dark provider must fail it FAST, or the sweep costs the full timeout on every dead provider and stops being the cheap loop it exists to be -- at 2m20s a 500-provider batch at concurrency 32 takes ~37 minutes instead of ~4")
	probeTimeout := flag.Duration("probe-timeout", 60*time.Second, "per-provider probe timeout, and the per-source deadline within a probe")
	skipConfinementCheck := flag.Bool("skip-confinement-check", false, "DANGEROUS: start even if this host can reach a geolocation api directly. Only for a one-shot manual probe on a host you know is not the operator's; a direct lookup records the OPERATOR's location for the provider and exposes the operator's address to the api")
	confinementTimeout := flag.Duration("confinement-timeout", 3*time.Second, "per-address deadline for the startup confinement self-check; a timeout counts as blocked. Must be at least "+confinement.MinTimeout.String())
	var confinementAddrs addressList
	publicAPIURL := flag.String("public-api-url", "", "the address the api answers on FROM THE PUBLIC INTERNET, used as the operator bandwidth target. This is not -api-url: control-plane calls go prober -> api directly (an internal name on docker), but the bandwidth target travels prober -> platform -> provider -> internet -> api, so it needs the public address. Empty drops the operator target and measures the cdn only")
	egressHealthAll := flag.Bool("egress-health-all", false, "run EVERY destination in the egress-health table instead of a random sample. The full table is the only way this exercises CONCURRENCY, since a sample never asks the provider to carry the full parallel load a real client would -- but the whole health run must still fit inside one -probe-timeout, and spreading it over the full table's rounds leaves each request far less than the cold-tunnel floor unless -probe-timeout is raised to match. The prober refuses to start rather than run below that floor and charge honest providers with cold-start timeouts, so setting this requires a longer -probe-timeout; it names the value")
	flag.Var(&confinementAddrs, "confinement-address", "ip:port the confinement self-check should dial instead of resolving the probe hosts; repeatable. For a jail where dns is legitimately blocked: supply the address of every geolocation source AND every egress-health destination here and the check stays real. The host part must be an ip literal, not a name")
	dueURL := flag.String("due-url", "", "url of the server's due-provider endpoint; empty derives <api-url>/network/provider-egress-due")
	dueLimit := flag.Int("due-limit", 100, "how many due providers to ask the server for per pass; the server clamps this to its own configured maximum, which defaults to 500 but is raised per deployment (provider_egress_due.yml)")
	shardCount := flag.Int("shard-count", 1, "number of probers sharing this server's due queue. 1 (the default) means this prober takes the whole queue. Above 1 the server hands this prober only the slice matching -shard-index, so N probers divide the fleet instead of each probing all of it -- without this the queue hands the SAME rows to every prober and adding hosts buys nothing")
	shardIndex := flag.Int("shard-index", 0, "which slice of the due queue this prober takes, 0 <= index < -shard-count. Ignored when -shard-count is 1")
	skipBandwidth := flag.Bool("skip-bandwidth", false, "do not measure provider bandwidth. The measurement rides the tunnel the geolocation probe already opened and is regulated by the server's hourly byte budget, so leaving it on is the intended mode; this is for a pass where the extra wall clock per provider matters more than the data")
	bandwidthTimeout := flag.Duration("bandwidth-timeout", bandwidth.DefaultTimeout, "per-target wall-clock cap for one bandwidth measurement. There are two targets, so this bounds the added time per provider at twice this value")
	pinRefreshInterval := flag.Duration("pin-refresh-interval", time.Hour, "how often to re-fetch the geolocation certificate pins from the server. The server re-observes them every 6h, so an hour is ample. A refresh that fails keeps the last good set -- the prober never degrades to unpinned -- but a set that is never refreshed goes stale, so this is not disableable")
	bandwidthCDNURL := flag.String("bandwidth-cdn-url", bandwidth.CDNTestURL, "the second bandwidth target: a size-parameterised public download (<url>?bytes=N). Measured separately from the operator target and never averaged with it -- a provider prioritising one path and not the other is only visible in two figures")
	flag.Parse()

	// Env fallback, applied only after parsing so the secret is never a flag
	// default and can never be rendered by flag.Usage(). An explicit flag
	// still wins, matching the previous precedence.
	envFallback(byJwt, "UR_PROBER_BY_JWT")
	envFallback(operatorSecret, "UR_OPERATOR_SECRET")

	var missing []string
	if *apiURL == "" {
		missing = append(missing, "-api-url")
	}
	if *platformURL == "" {
		missing = append(missing, "-platform-url")
	}
	// -by-jwt is deliberately NOT in this list any more: an empty one is
	// fetched from the server below (see fetchByJwtIfEmpty), which is the
	// whole point of the prober-credential endpoint. -operator-secret stays
	// required precisely because that fetch authenticates with it.
	if *operatorSecret == "" {
		missing = append(missing, "-operator-secret (or UR_OPERATOR_SECRET)")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: missing required flag(s): %s\n\n", strings.Join(missing, ", "))
		flag.Usage()
		os.Exit(2)
	}

	// M1: a negative -interval would otherwise fall straight into
	// time.After, which treats a negative duration as "fire immediately" --
	// degenerating the sleep loop into back-to-back passes with no pause
	// between them and no indication why. Fail fast instead.
	if *interval < 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -interval must not be negative (got %s)\n\n", *interval)
		flag.Usage()
		os.Exit(2)
	}
	if *blackholeInterval < 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -blackhole-interval must not be negative (got %s); use 0 to disable the sweep\n\n", *blackholeInterval)
		flag.Usage()
		os.Exit(2)
	}
	if 0 < *blackholeInterval {
		if *blackholeConcurrency < 1 {
			fmt.Fprintf(os.Stderr, "egress-prober: -blackhole-concurrency must be positive (got %d)\n\n", *blackholeConcurrency)
			flag.Usage()
			os.Exit(2)
		}
		if *blackholeTimeout <= 0 {
			fmt.Fprintf(os.Stderr, "egress-prober: -blackhole-timeout must be positive (got %s)\n\n", *blackholeTimeout)
			flag.Usage()
			os.Exit(2)
		}
		if *blackholeLimit < 1 {
			fmt.Fprintf(os.Stderr, "egress-prober: -blackhole-limit must be positive (got %d)\n\n", *blackholeLimit)
			flag.Usage()
			os.Exit(2)
		}
	}

	// M5: -probe-timeout 0 disables BOTH the http.Client.Timeout and the
	// manual TLS handshake timeout in providertunnel's DialTLSContext (see
	// providertunnel/tunnel.go: `if timeout > 0`), since a zero
	// time.Duration is the Go idiom for "no timeout" in both places. A
	// negative value is nonsensical for either. Either way, a provider that
	// simply never responds would hang a probe (and the goroutine slot it
	// holds) forever instead of freeing up for the next pass.
	if *probeTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -probe-timeout must be positive (got %s)\n\n", *probeTimeout)
		flag.Usage()
		os.Exit(2)
	}

	// A tiny -confinement-timeout turns the self-check off while it keeps
	// logging success, which is worse than turning it off honestly. The dial
	// budget has to be long enough that a failure means "the packet did not get
	// through"; below that every dial fails on the clock instead, every address
	// looks blocked whether or not it is, and the check reports a pass having
	// tested nothing. Observed on one unconfined host in the same second:
	// -confinement-timeout 10ms correctly reported "not confined", 1ms reported
	// "passed". Rejecting <= 0 was never enough -- the same reasoning applies to
	// any value too short to complete a connection.
	if *confinementTimeout < confinement.MinTimeout {
		fmt.Fprintf(os.Stderr, "egress-prober: -confinement-timeout must be at least %s (got %s): a shorter deadline expires before a direct connection could complete, so every geolocation address would look blocked whether or not it is and the self-check would report a pass having tested nothing\n\n", confinement.MinTimeout, *confinementTimeout)
		flag.Usage()
		os.Exit(2)
	}

	// The server answers 400 to a non-positive limit rather than clamping it:
	// limit=0 would come back as an empty list, indistinguishable from
	// "nothing is due". Fail here instead of once per pass.
	if *dueLimit < 1 {
		fmt.Fprintf(os.Stderr, "egress-prober: -due-limit must be positive (got %d)\n\n", *dueLimit)
		flag.Usage()
		os.Exit(2)
	}

	// Same reasoning as -due-limit. A shard outside the range makes the server
	// return an empty slice on every pass, which reads as "nothing is due"
	// rather than as a misconfiguration, so a prober would sit probing nothing
	// indefinitely. Fail at startup instead.
	if *shardCount < 1 {
		fmt.Fprintf(os.Stderr, "egress-prober: -shard-count must be at least 1 (got %d)\n\n", *shardCount)
		flag.Usage()
		os.Exit(2)
	}
	if *shardIndex < 0 || *shardCount <= *shardIndex {
		fmt.Fprintf(
			os.Stderr,
			"egress-prober: -shard-index must satisfy 0 <= index < -shard-count (got index %d, count %d)\n\n",
			*shardIndex, *shardCount,
		)
		flag.Usage()
		os.Exit(2)
	}

	// A non-positive -pin-refresh-interval would make every pass re-fetch the
	// pin set (<= 0 elapsed is always true), turning a control-plane call the
	// server expects hourly into one per pass, and a zero value reads like
	// "off" -- which it must never be, since a set that is never refreshed is
	// exactly the stale-pin problem this replaced.
	if *pinRefreshInterval <= 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -pin-refresh-interval must be positive (got %s)\n\n", *pinRefreshInterval)
		flag.Usage()
		os.Exit(2)
	}

	// The health run has to fit inside one -probe-timeout AND leave each
	// request at least the cold-tunnel floor. Those two are in tension: the
	// full table takes 14 rounds at its raised concurrency, so a 60s probe
	// timeout leaves 4.3s per request -- below the 6s this package's own
	// DefaultConcurrency comment rejects as "cold-start timeouts charged to
	// providers as blackholes", and well below the 10s floor. Rather than
	// silently manufacture that, refuse to start and name the value that
	// would work. A sampled run at the default clears the floor comfortably
	// (12s), which is why sampling is the default.
	if opts := egressHealthOptions(*probeTimeout, *egressHealthAll); opts.PerRequestTimeout < egresshealth.DefaultPerRequestTimeout {
		need := time.Duration(egressHealthRounds(*egressHealthAll)) * egresshealth.DefaultPerRequestTimeout
		fmt.Fprintf(os.Stderr,
			"egress-prober: -probe-timeout %s leaves %s per egress-health request, below the %s cold-tunnel floor;\n"+
				"  every request would be at risk of timing out and being recorded as a provider failure.\n"+
				"  Either raise -probe-timeout to at least %s, or drop -egress-health-all to sample the table instead.\n\n",
			*probeTimeout, opts.PerRequestTimeout.Round(time.Millisecond), egresshealth.DefaultPerRequestTimeout, need)
		flag.Usage()
		os.Exit(2)
	}

	// A negative cache ttl makes recentlyProbed always false, silently
	// disabling the enumeration cache. Every other duration flag is validated;
	// this one degraded quietly instead, which is the opposite of how the rest
	// of this startup path treats a value it cannot honour.
	if *cacheTTL < 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -cache-ttl must not be negative (got %s); use 0 to disable the enumeration cache\n\n", *cacheTTL)
		flag.Usage()
		os.Exit(2)
	}

	// A non-positive bandwidth timeout would hand context.WithTimeout an
	// already-expired deadline, so every measurement would fail instantly and
	// still have spent a byte reservation getting there.
	if *bandwidthTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -bandwidth-timeout must be positive (got %s)\n\n", *bandwidthTimeout)
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The first signal cancels ctx and begins a graceful wind-down (the
	// scheduler stops spawning and the in-flight probes fail fast). Undo the
	// signal capture at that point rather than at exit: NotifyContext keeps
	// swallowing signals for as long as it is registered, so without this a
	// second Ctrl-C during the wind-down would be silently discarded and the
	// operator could not force-quit a probe stuck in teardown.
	context.AfterFunc(ctx, stop)

	// The confinement self-check runs before anything else touches the
	// network. See checkConfinement.
	if *skipConfinementCheck {
		log.Printf("egress-prober: WARNING -skip-confinement-check is set: the startup confinement self-check is DISABLED.")
		log.Printf("egress-prober: WARNING if this host can reach a geolocation api directly, a probe that fails to tunnel records the OPERATOR's own location for the provider and exposes the operator's address to third-party apis. Do not set this on the operator's deployment.")
	} else if err := checkConfinement(ctx, (&net.Dialer{}).DialContext, net.DefaultResolver.LookupHost, confinementAddrs, *confinementTimeout, append(bandwidthProbeHosts(*skipBandwidth, *bandwidthCDNURL), egresshealth.BlackholeHosts()...)...); err != nil {
		log.Printf("egress-prober: confinement self-check failed: %s", err)
		// ErrNoEvidence is not a claim that this host is unconfined -- it is
		// the check saying it could not find out -- so the "go and confine it"
		// advice would be misleading. Its own message carries the two remedies.
		if !errors.Is(err, confinement.ErrNoEvidence) {
			log.Printf("egress-prober: this process must not be able to reach a geolocation api except through a provider tunnel. Confine it (a restricted docker network, or systemd IPAddressDeny=any with IPAddressAllow for the operator server only) and start it again.")
		}
		os.Exit(1)
	}

	// Built here rather than after the jwt because the credential fetch below
	// needs it. Nothing in it depends on the jwt: it authenticates with the
	// operator secret alone, which is what makes fetching the jwt possible at
	// all.
	operator := &ingest.Client{
		ServerURL:      *apiURL,
		OperatorSecret: *operatorSecret,
		DueURL:         *dueURL,
		ShardIndex:     *shardIndex,
		ShardCount:     *shardCount,
		HTTP:           controlplane.NewHTTPClient(30 * time.Second),
	}

	// The jwt, if the deployment did not supply one. This sits ABOVE
	// parseByJwtClientId on purpose: a fetched jwt then travels the identical
	// path an explicitly supplied one does -- same parse, same client id, same
	// tunnel config -- so a credential the server hands over but that this
	// process cannot use still fails loudly, right here, instead of becoming a
	// fleet-wide outage that looks like nothing at all.
	//
	// It also sits below the confinement self-check, which must stay the first
	// thing that touches the network. The operator's own server is the one
	// direct call the prober is allowed to make, so this is the earliest point
	// at which it may run.
	switch err := fetchByJwtIfEmpty(ctx, byJwt, operator, credentialPollInitial, credentialPollMax); {
	case err == nil:
	case ctx.Err() != nil:
		// Interrupted while waiting for the server's bootstrap task. That is a
		// shutdown, not a broken deployment, and the same reasoning as the
		// pass-result exit codes below applies: it must not exit non-zero and
		// blame a configuration that is fine.
		log.Printf("egress-prober: interrupted while waiting for the prober credential (%v); nothing was probed", ctx.Err())
		return
	default:
		log.Printf("egress-prober: %s", err)
		os.Exit(1)
	}

	clientId, err := parseByJwtClientId(*byJwt)
	if err != nil {
		log.Fatalf("parse by-jwt client id: %s", err)
	}

	// The credential self-check runs before the first tunnel, for the same
	// reason the confinement self-check runs before the first request: a fault
	// the prober cannot detect at runtime has to be caught here or not at all.
	switch err := checkCredential(ctx, operator.HTTP, *apiURL, *byJwt); {
	case err == nil:
		log.Printf("egress-prober: credential self-check passed: the server accepts the byJwt")
	case errors.Is(err, errCredentialRejected):
		log.Printf("egress-prober: credential self-check FAILED: %s", err)
		log.Printf("egress-prober: the byJwt parses but the server refuses it -- it has expired, or it predates a claim the server now enforces. Probes would not fail loudly: the operator-secret calls would keep working while every tunnel carried nothing and every provider was recorded as no_consensus. Mint a fresh network client jwt (POST /network/auth-client) and set UR_PROBER_BY_JWT to it.")
		os.Exit(1)
	default:
		log.Printf("egress-prober: WARNING credential self-check inconclusive: %s", err)
		log.Printf("egress-prober: continuing, because being unable to check is not evidence the credential is bad. If every provider comes back no_consensus with ok=0/N, suspect the byJwt first.")
	}

	// Pins is deliberately NOT set here: it is fetched from the server below
	// and read afresh on every tunnel Open, so an hourly refresh reaches the
	// next provider rather than only the next process.
	tunnelCfg := providertunnel.Config{
		ApiURL:            *apiURL,
		PlatformURL:       *platformURL,
		ByJwt:             *byJwt,
		ClientId:          clientId,
		DeviceDescription: "egress prober",
		DeviceSpec:        "egress-prober",
		Version:           "0.0.0",
	}

	// The startup fetch. This is a separate call site from the refresh in the
	// pass loop below, and the difference between them is the whole fail-closed
	// property: THIS one exits, the other one keeps the last good set. Folding
	// them into one helper with a "tolerate failure" flag would put both
	// behaviours one wrong argument apart.
	//
	// No pin set means no probing. Not an empty map (providertunnel.Open
	// refuses that, and it must keep refusing it), not the hardcoded set this
	// replaced, and above all not unpinned: the geolocation lookup is issued
	// through the provider under test, so an unpinned probe lets that provider
	// substitute a certificate and forge its own apparent location. It would
	// still look like a successful pass.
	pins := &pinSet{}
	initialPins, err := fetchGeolocationPins(ctx, operator)
	if err != nil {
		log.Printf("egress-prober: %s", err)
		log.Printf("egress-prober: refusing to start. The geolocation lookups ride the tunnel of the provider being measured, and the certificate pins are what stop that provider forging its own location -- so no pin set means no probing, never an unpinned probe. Check -api-url and -operator-secret, and that the server has observed the pins (its refresh job runs every 6h).")
		os.Exit(1)
	}
	pins.set(initialPins)
	log.Printf("egress-prober: geolocation pins fetched from the server for %d host(s): %s", len(initialPins), strings.Join(sortedHosts(initialPins), " "))

	// Both bandwidth targets are reached THROUGH the provider tunnel, so both
	// their hosts have to be in the tunnel's allowlist (see newProber) or the
	// dialer refuses them before a byte moves.
	//
	// Note what this means for the operator target: the X-UR-Operator-Secret
	// header now traverses a provider-controlled path. The connection is
	// ordinary WebPKI-verified TLS, so a provider on the path cannot read it
	// without a mis-issued certificate for the operator's own api host -- the
	// same protection any https client has, and the same one the egress-health
	// destinations rely on. It is called out because the consequence differs:
	// that secret gates location ingest for the whole fleet, where an
	// egress-health destination gates nothing. Pinning the api host would close
	// it, but the pin is deployment-specific and not knowable here.
	bandwidthSampler := (*bandwidth.Sampler)(nil)
	bandwidthTargets := []bandwidth.Target{}
	if !*skipBandwidth {
		// The cdn target is always present; the operator target is dropped when
		// no public api url is configured, because an internal name fails from
		// the far side of the tunnel for EVERY provider and reads as a
		// fleet-wide fault rather than a misconfiguration.
		bandwidthTargets = []bandwidth.Target{
			{Name: "cdn", Source: bandwidth.SourceCDN, URL: *bandwidthCDNURL},
		}
		if strings.TrimSpace(*publicAPIURL) != "" {
			bandwidthTargets = append([]bandwidth.Target{
				bandwidth.OperatorTarget(*publicAPIURL, *operatorSecret),
			}, bandwidthTargets...)
		} else {
			log.Printf("egress-prober: no -public-api-url, measuring the cdn target only (the operator target cannot be reached through a provider tunnel by its internal name)")
		}
		bandwidthSampler = &bandwidth.Sampler{
			Targets: bandwidthTargets,
			Reserve: operator,
			Submit:  operator,
			Timeout: *bandwidthTimeout,
		}
	}

	dueScheduler, enumScheduler := newSchedulers(
		newProber(tunnelCfg, pins, *probeTimeout, operator, *egressHealthAll, bandwidthSampler, bandwidth.TargetHosts(bandwidthTargets)),
		*concurrency,
		*cacheTTL,
	)

	if 0 < *blackholeInterval {
		sweeper := &blackholeSweeper{
			operator:    operator,
			tunnelCfg:   tunnelCfg,
			pins:        pins,
			timeout:     *blackholeTimeout,
			concurrency: *blackholeConcurrency,
			limit:       *blackholeLimit,
		}
		go sweeper.run(ctx, *blackholeInterval)
	}

	// I3: a single-shot run (-interval 0) is the mode the README recommends
	// for external cron/systemd scheduling, which decides success or
	// failure purely from the exit code -- so this process must not report
	// success (exit 0) when it accomplished nothing. Two cases are treated
	// as failure below: the provider list could not be fetched at all, and
	// a pass that ran but submitted nothing while recording failures (e.g.
	// every probe hit the same wrong -platform-url, or the jwt was
	// revoked -- a permanently broken configuration, not a fluke). A pass
	// with zero providers to probe (submitted=0, failed=0) is NOT a
	// failure -- there was simply nothing to do.
	//
	// The long-running loop (-interval > 0) deliberately does NOT exit on
	// either condition: a systemd-managed process should keep retrying
	// through a transient server blip rather than dying, but it does still
	// log clearly so the failure is visible (e.g. via journalctl) even
	// though the process itself stays up.
	for {
		// The refresh call site. Unlike the startup fetch it never exits and
		// never clears the set: a server blip must not be able to stop the
		// fleet, and a stale-but-valid pin still fails closed on a real MITM.
		// The intermediate pin is what keeps a set usable across routine leaf
		// rotation in the meantime.
		refreshGeolocationPins(ctx, operator, pins, *pinRefreshInterval)

		providers, serverDriven, err := selectProviders(ctx, operator, *dueLimit, *apiURL, *byJwt)
		if err != nil {
			log.Printf("select providers: %s", err)
			// Same reasoning as the pass result below: a fetch that failed
			// because the operator interrupted the process is a shutdown, not
			// a broken deployment, and must not exit non-zero.
			if *interval == 0 && ctx.Err() == nil {
				log.Printf("egress-prober: single-shot pass could not fetch the provider list; exiting non-zero")
				os.Exit(1)
			}
		} else {
			scheduler := enumScheduler
			if serverDriven {
				scheduler = dueScheduler
			}
			sum := scheduler.Run(ctx, providers)
			log.Printf("pass: server_driven=%t attempted=%d submitted=%d skipped=%d failed=%d",
				serverDriven, sum.Attempted, sum.Submitted, sum.Skipped, sum.Failed)
			// A pass cut short by SIGTERM is not a pass that failed. The
			// scheduler stops spawning on cancellation, but the probes
			// already in flight fail on the dead context and land in
			// sum.Failed -- so without this guard an operator pressing Ctrl-C
			// got exit 1 and a message blaming the providers, which is the
			// same misdiagnosis the cancellation fix was written to remove.
			// The shutdown is logged instead and the exit stays 0: nothing
			// about the fleet was learned either way.
			if *interval == 0 {
				switch {
				case ctx.Err() != nil:
					log.Printf("egress-prober: single-shot pass interrupted (%v) after %d submitted, %d failed; exiting zero", ctx.Err(), sum.Submitted, sum.Failed)
				case sum.Submitted == 0 && 0 < sum.Failed:
					log.Printf("egress-prober: single-shot pass submitted nothing and recorded %d failure(s); exiting non-zero", sum.Failed)
					os.Exit(1)
				}
			}
		}
		if *interval == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}

// newProber wires the production prober: a tunnel per provider, the
// geolocation consensus through it, submission and attempt reporting to the
// operator's server.
//
// Attempts is not optional in production. The server defers a provider from
// the due queue when a probe was recently ATTEMPTED, not only when one
// succeeded, so a prober that does not report leaves every unprobeable
// provider at the head of the queue forever -- see prober.ProbeOne.
// The pin set is passed in rather than baked into tunnelCfg because it is
// refreshed while the process runs: every Open takes a copy of tunnelCfg and
// fills Pins from the CURRENT set, so an hourly refresh takes effect on the
// next provider instead of the next restart. providertunnel.Open's
// ErrPinsRequired stays the last-ditch guard on that path and is deliberately
// not pre-empted here.
func newProber(
	tunnelCfg providertunnel.Config,
	pins *pinSet,
	probeTimeout time.Duration,
	operator *ingest.Client,
	allDestinations bool,
	bandwidthSampler *bandwidth.Sampler,
	bandwidthHosts []string,
) *prober.Prober {
	return fleetprobe.NewFullProber(fleetprobe.FullOptions{
		TunnelConfig:    tunnelCfg,
		Pins:            pins.get,
		ProbeTimeout:    probeTimeout,
		Concurrency:     1,
		AllDestinations: allDestinations,
		Submit:          operator,
		Attempts:        operator,
		HealthResults:   operator,
		Bandwidth:       bandwidthSampler,
		BandwidthHosts:  bandwidthHosts,
	})
}

// egressHealthOptions derives the health check's bounds from -probe-timeout so
// that a FULL health run costs at most ONE additional -probe-timeout per
// provider, whatever the provider does.
//
// The arithmetic matters, because the naive version is a 4x regression on the
// pass. There is no per-provider deadline in the scheduler -- the bound on a
// probe comes from the http.Client timeout and geolocate's per-source cap -- so
// whatever budget is handed to the health check is added to the wall clock of
// every probe against a provider that swallows requests. Giving each health
// request a full -probe-timeout, over ceil(9/3) = 3 sequential rounds, would
// add 3 x -probe-timeout: at the defaults, a blackholing provider would go from
// ~60s to ~240s, and a 100-provider batch at -concurrency 4 from ~25 min to
// ~100 min against a 1h -interval.
//
// Instead the WHOLE run gets one -probe-timeout, divided across the rounds. A
// blackholing provider therefore costs about 2 x -probe-timeout in total
// (geolocation, then health), not 4x.
//
// Per-request that is 12s at the 60s default (5 rounds of the 30-destination
// sample), against 60s for a geolocation source. The shorter budget is
// defensible here and not merely convenient: by the time the health check runs,
// the multiclient session is established and the tunnel has already carried the
// geolocation lookups. A health request pays a name resolution (often already
// cached in-tunnel by then), a TCP connect and a TLS handshake -- not the
// cold-start the geolocation cap is sized for. If that turns out to be wrong in
// the field it shows up as a specific, recognisable shape: timeouts spread
// evenly across all classes, on providers whose geolocation succeeded.
// allDestinations selects the geometry of the run being sized. Both paths get
// the same one -probe-timeout budget; they differ only in how many rounds that
// budget is divided across, because a full-table run raises concurrency and
// still needs many more rounds than a sample.
//
// Deriving the per-request bound from one geometry and then applying it to the
// other is precisely the defect this signature exists to prevent: sizing
// per-request off the 5 sampled rounds and then letting the full table's 14
// rounds multiply it drew 2.8x -probe-timeout at the shipped default, so a
// blackholing provider cost ~3.8x per probe -- the regression the arithmetic
// above is written to avoid, arriving through the default configuration.
// egressHealthRounds is how many sequential rounds a run takes, which is what
// one -probe-timeout gets divided across. It is the single place the two
// geometries are chosen, so the budget check at startup and the options the
// run actually uses can never disagree.
func egressHealthRounds(allDestinations bool) int {
	return fleetprobe.EgressHealthRounds(allDestinations)
}

func egressHealthOptions(probeTimeout time.Duration, allDestinations bool) egresshealth.Options {
	return fleetprobe.EgressHealthOptions(probeTimeout, allDestinations)
}

// newSchedulers returns the scheduler for a server-driven pass and the one for
// the enumeration fallback.
//
// They are separate because the two passes have different schedules and must
// not share a cache. When the server picks the batch it owns the schedule --
// observed_at and attempt_at in its database, which survive a prober restart --
// so re-filtering that batch through an in-memory ttl would drop providers the
// server just said were due, with the two schedules disagreeing and no way to
// tell which won. The fallback pass has no server-side schedule behind it, so
// it keeps the -cache-ttl behaviour exactly as before.
func newSchedulers(p *prober.Prober, concurrency int, cacheTTL time.Duration) (dueScheduler *prober.Scheduler, enumScheduler *prober.Scheduler) {
	return &prober.Scheduler{
			Prober:      p,
			Concurrency: concurrency,
			CacheTTL:    0,
		}, &prober.Scheduler{
			Prober:      p,
			Concurrency: concurrency,
			CacheTTL:    cacheTTL,
		}
}

// dueLister is the server's due-provider endpoint, injected so selectProviders
// is testable without one.
type dueLister interface {
	Due(ctx context.Context, limit int) ([]string, error)
}

// selectProviders returns the providers to probe this pass, and whether the
// server chose them.
//
// The server's due list is authoritative when it answers: it is computed from
// observed_at and attempt_at in the database, so it survives a prober restart
// and does not re-probe the whole population after one.
//
// Exactly one error falls back to enumerating the population locally: 404,
// meaning the server has not deployed the endpoint. Everything else surfaces.
// A 401 in particular must NOT fall back -- that is a wrong operator secret,
// and quietly degrading to enumeration would produce a full-looking pass whose
// every submission is rejected by that same secret, hiding the actual fault.
func selectProviders(ctx context.Context, due dueLister, limit int, apiURL string, byJwt string) ([]string, bool, error) {
	ids, err := due.Due(ctx, limit)
	switch {
	case err == nil:
		return ids, true, nil
	case errors.Is(err, ingest.ErrDueUnsupported):
		log.Printf("egress-prober: the server has no %s endpoint; falling back to enumerating every provider (upgrade the server to let it schedule probes)", "/network/provider-egress-due")
		ids, err := listProviders(ctx, apiURL, byJwt)
		return ids, false, err
	case errors.Is(err, ingest.ErrUnauthorized):
		return nil, false, fmt.Errorf("the server rejected the operator secret; check -operator-secret against ingest_secret in the server's provider_egress.yml: %w", err)
	default:
		return nil, false, err
	}
}

// confinementPort is the port the self-check dials. Every geolocate source and
// every egresshealth destination is https on the default port, and https is the
// only thing a probe from this process would ever be. egresshealth's
// TestEveryDestinationIsHTTPSOn443 keeps that true from the other side -- a
// destination on another port would silently fall outside this check.
const confinementPort = "443"

// probeHosts is every third-party host this process reaches through a tunnel:
// the pinned geolocation sources, the egress-health destinations, and any
// extra hosts the caller names -- in practice the bandwidth CDN target, which
// is third-party and configurable via -bandwidth-cdn-url. It is what the
// confinement self-check must prove unreachable directly, and what an
// operator translates into -confinement-address entries.
//
// The operator's OWN api host is deliberately absent: it is not third-party,
// and a deployment may legitimately allow the prober to reach it directly.
//
// Both lists are DERIVED from the tables that own them (geolocate.SourceHosts,
// egresshealth.DestinationHosts) for the reason spelled out on each: a
// hand-maintained second copy drifts on the first table change, and the check
// keeps reporting a pass while no longer covering a real endpoint.
//
// The egress-health destinations belong here for the same reason as the
// geolocation ones, though the harm differs. A direct geolocation lookup
// records the OPERATOR's location for a provider. A direct egress-health check
// is worse in one specific way: it would pass -- the operator's own host can
// obviously reach Cloudflare and Amazon -- and so would certify a blackholing
// provider as healthy, which is the exact inversion of the signal.
func probeHosts(extra ...string) []string {
	seen := map[string]bool{}
	var hosts []string
	all := append(geolocate.SourceHosts(), egresshealth.DestinationHosts()...)
	all = append(all, extra...)
	for _, h := range all {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts
}

// bandwidthProbeHosts returns the bandwidth CDN target's host, if the
// bandwidth probe will run at all. It is a third-party host reached through
// the tunnel, so the confinement check covers it like any other; the operator
// target is deliberately excluded, being the operator's own api.
func bandwidthProbeHosts(skipBandwidth bool, cdnURL string) []string {
	if skipBandwidth {
		return nil
	}
	u, err := url.Parse(cdnURL)
	if err != nil || u.Hostname() == "" {
		// A malformed -bandwidth-cdn-url is caught where it is used; the
		// self-check simply has nothing to add for it here.
		return nil
	}
	return []string{u.Hostname()}
}

// addressList collects the repeatable -confinement-address flag.
//
// Each value must be "ip:port" with a literal address, not a name. A name here
// would defeat the flag's entire purpose: it exists for the deployment where
// dns is blocked, so a name could not be resolved at dial time either and the
// check would be back to dialing something guaranteed to fail at resolution --
// no evidence, reported as a pass.
type addressList []string

func (a *addressList) String() string { return strings.Join(*a, " ") }

func (a *addressList) Set(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", v, err)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("%q: the host part must be an ip literal, not a name -- this flag exists for a jail where dns is blocked, and a name could not be resolved at dial time either", v)
	}
	if port == "" {
		return fmt.Errorf("%q: a port is required", v)
	}
	*a = append(*a, v)
	return nil
}

// checkConfinement refuses to let the prober start unless a direct connection
// to every geolocation endpoint fails.
//
// The prober's whole guarantee is that a geolocation api only ever sees a
// provider's address, never the operator's. That is enforced OUTSIDE this
// process, because the beta deployment runs docker compose and the mainstream
// deployment does not use docker at all: a restricted docker network there,
// systemd IPAddressDeny=any plus a narrow IPAddressAllow here. Neither
// mechanism is inspectable portably, and creating a namespace for itself would
// need CAP_NET_ADMIN on a component that runs completely unprivileged today.
//
// So the check tests the property rather than the mechanism. If a direct
// connection succeeds, the confinement is absent and the prober exits: it does
// not "try anyway", because the failure mode of trying is silent and
// irreversible -- a probe that could not tunnel would record the OPERATOR's
// location for that provider, and the operator's address would be handed to
// three third-party apis.
//
// The addresses come from probeHosts -- geolocate.SourceHosts plus
// egresshealth.DestinationHosts -- resolved here at startup, so the repo holds
// exactly one copy of each endpoint list. A hand-maintained second copy would
// drift on the first endpoint change and the check would keep passing while no
// longer covering a real endpoint.
//
// This does not replace the Go-level fail-closed behaviour (lookups only ever
// run on a tunnel-bound http.Client; providertunnel refuses any host outside
// the pin allowlist). It is the outer layer that backs it.
//
// Inability to verify is not evidence of confinement. Every outcome in which
// the check could not obtain real evidence is a refusal to start, never a
// pass: no resolvable host (confinement.ErrNoEvidence), a timeout too short to
// mean anything (confinement.ErrInvalidTimeout, rejected at flag validation),
// an empty endpoint list. Hosts that fail to resolve are NOT dialed by name --
// that dial fails at resolution and proves nothing -- and when only some of
// them resolve, the shortfall is logged as a WARNING so a degraded check never
// reads like a complete one.
func checkConfinement(ctx context.Context, dial confinement.DialFunc, lookup confinement.LookupFunc, explicitAddrs []string, timeout time.Duration, extraHosts ...string) error {
	hosts := probeHosts(extraHosts...)

	var addrs, unresolved []string
	if len(explicitAddrs) > 0 {
		// The escape hatch for a jail where dns legitimately cannot work.
		// Resolution is skipped entirely and exactly these addresses are
		// dialed, which keeps a real check available there instead of pushing
		// the operator towards -skip-confinement-check, which is no check at
		// all. Keeping them in sync with the geolocation endpoints is the
		// operator's job, so the endpoint list is logged alongside them.
		addrs = explicitAddrs
		log.Printf("egress-prober: confinement self-check: dialing the %d address(es) given with -confinement-address, skipping resolution: %s (probe hosts: %s -- keep these addresses current with that list)",
			len(addrs), strings.Join(addrs, " "), strings.Join(hosts, " "))
	} else {
		// Resolution is bounded so that a blocked resolver cannot hang startup
		// -- under a real deny-all confinement dns is blocked too. The budget is
		// PER HOST, not for the whole list: confinement.Addresses resolves
		// sequentially, and this list grew from 3 geolocation hosts to 12 when
		// the egress-health destinations joined it. Keeping one flat budget for
		// the whole loop would have quietly made the check four times more
		// likely to time out mid-list on a slow resolver -- which does not fail
		// loudly, it degrades: the later hosts land in `unresolved`, the check
		// reports a DEGRADED pass, and the endpoints it stopped covering are
		// exactly the ones added last. (Measured here with a working resolver:
		// 12 hosts -> 49 addresses in 25ms, so this is headroom, not a
		// requirement.)
		resolveCtx, cancel := context.WithTimeout(ctx, timeout*time.Duration(len(hosts)))
		var err error
		addrs, unresolved, err = confinement.Addresses(resolveCtx, lookup, hosts, confinementPort)
		cancel()
		if err != nil {
			return err
		}

		log.Printf("egress-prober: confinement self-check: %d probe host(s) -> %d address(es): %s", len(hosts), len(addrs), strings.Join(addrs, " "))
		if 0 < len(unresolved) && 0 < len(addrs) {
			log.Printf("egress-prober: WARNING confinement self-check is DEGRADED: %d of %d probe host(s) could not be resolved and were NOT tested: %s. Whether this host can reach them directly is unknown. Allow dns resolution for the prober, or pass -confinement-address <ip:port> for each of them.",
				len(unresolved), len(hosts), strings.Join(unresolved, " "))
		}
	}

	if err := confinement.Verify(ctx, dial, addrs, unresolved, timeout); err != nil {
		if errors.Is(err, confinement.ErrNoEvidence) {
			// The vacuous pass this replaced: with dns blocked, every host fell
			// back to a bare name, every dial failed at resolution, and the
			// check reported success without having tested one address.
			return fmt.Errorf("%w -- allow dns resolution for the prober, or pass -confinement-address <ip:port> once per probe endpoint (%s) so the check dials them directly", err, strings.Join(hosts, " "))
		}
		return err
	}
	log.Printf("egress-prober: confinement self-check passed: %d address(es) tested, none directly reachable", len(addrs))
	return nil
}

// credentialFetcher is the server's prober-credential endpoint, injected so
// fetchByJwtIfEmpty is testable without one.
type credentialFetcher interface {
	ProberCredential(ctx context.Context) (*ingest.ProberCredential, error)
}

// credentialPollInitial and credentialPollMax bound the wait for a credential
// the server has not minted yet.
//
// The server's bootstrap task runs immediately and then every 6h, so a prober
// brought up alongside a fresh deployment can still win the startup race. That is a WAIT, not a
// crash: exiting would put a supervised process into a restart loop that
// re-runs the confinement self-check and re-fetches on every restart, and
// which reads in journald as a broken prober rather than as one patiently
// doing the right thing. Starting at 30s keeps the pickup prompt when the task
// runs minutes later; capping at 5m keeps a six-hour wait to ~75 requests.
const (
	credentialPollInitial = 30 * time.Second
	credentialPollMax     = 5 * time.Minute
)

// nextBackoff doubles cur without exceeding max. Split out from the loop so the
// schedule is testable without sleeping through it.
func nextBackoff(cur, max time.Duration) time.Duration {
	if max <= cur {
		return max
	}
	if doubled := cur * 2; doubled < max {
		return doubled
	}
	return max
}

// fetchByJwtIfEmpty fills *byJwt from the server's prober-credential endpoint
// when it is empty, waiting for the server's bootstrap task if it has to.
//
// The precedence is envFallback's, deliberately: an explicitly supplied value
// is left alone and the server is not even asked. That is what keeps the
// existing deployment -- which supplies UR_PROBER_BY_JWT today -- working
// exactly as it does now, and it is why this cannot be written as "fetch, then
// prefer the explicit one": that would still block startup on a server which
// has no credential yet, for a prober that never needed one.
//
// The three outcomes of the fetch map to three different behaviours, and
// keeping them apart is the whole point:
//
//   - not ready (404): the expected state before the bootstrap task has run.
//     Log it as a wait and ask again, forever, on a capped backoff. There is no
//     total deadline: "wait rather than crash-loop" has no useful upper bound
//     here, and a supervisor's own start timeout is the right place to impose
//     one if a deployment wants it. ctx is what ends the wait.
//   - unauthorized (401): a wrong -operator-secret. Fatal and immediate. A
//     secret the server rejects will be rejected on every retry, so polling
//     would turn a two-minute fix into an outage nobody is paged for.
//   - anything else: transient. Retry on the same backoff, but log the actual
//     error each time rather than the reassuring "not ready" line, because
//     these are the ones that might need a human.
func fetchByJwtIfEmpty(ctx context.Context, byJwt *string, f credentialFetcher, initial, max time.Duration) error {
	if *byJwt != "" {
		return nil
	}

	// Guards against a zero or negative interval turning the loop below into a
	// busy wait against the server (time.After fires immediately, and doubling
	// zero stays zero).
	if initial <= 0 {
		initial = time.Second
	}
	if max < initial {
		max = initial
	}

	log.Printf("egress-prober: no -by-jwt (or UR_PROBER_BY_JWT) was supplied; asking the server for the prober credential")

	backoff := initial
	for {
		cred, err := f.ProberCredential(ctx)
		switch {
		case err == nil:
			*byJwt = cred.ByClientJwt
			// The client id, never the jwt: this line goes to journald, and
			// the jwt is a credential. The id is what an operator needs to
			// match the prober against the server's record of it.
			log.Printf("egress-prober: got the prober credential from the server for client %s", cred.ClientId)
			return nil
		case errors.Is(err, ingest.ErrUnauthorized):
			return fmt.Errorf("the server rejected the operator secret when asked for the prober credential; check -operator-secret against ingest_secret in the server's provider_egress.yml: %w", err)
		case errors.Is(err, ingest.ErrCredentialNotReady):
			log.Printf("egress-prober: the server has not minted the prober credential yet; asking again in %s (its bootstrap task runs immediately and then every 6h)", backoff)
		default:
			log.Printf("egress-prober: could not get the prober credential: %s; asking again in %s", err, backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = nextBackoff(backoff, max)
	}
}

// envFallback fills *value from the named environment variable when the flag
// was not given. Reading the environment here, rather than through the flag's
// default, is what keeps the value out of flag.Usage() output.
func envFallback(value *string, envName string) {
	if *value == "" {
		*value = os.Getenv(envName)
	}
}

// pinSet holds the geolocation certificate pins currently in force.
//
// One writer (the pass loop's refresh) and one reader per tunnel Open, which
// runs on the scheduler's worker goroutines, so the mutex is load-bearing
// rather than decorative even though the refresh happens between passes today.
//
// It is only ever written with a set that has already passed
// validateGeolocationPins: there is exactly one path from the wire into this
// struct, and it refuses anything that does not cover every geolocation source
// host. A caller cannot half-populate it.
type pinSet struct {
	mu        sync.Mutex
	pins      map[string][]string
	fetchedAt time.Time
}

// get returns a copy, so a refresh cannot mutate the map a tunnel is already
// verifying against mid-probe.
func (s *pinSet) get() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]string, len(s.pins))
	for host, allowed := range s.pins {
		out[host] = append([]string(nil), allowed...)
	}
	return out
}

func (s *pinSet) set(pins map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins = pins
	s.fetchedAt = time.Now()
}

// age reports how long ago the set was last successfully fetched.
func (s *pinSet) age() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.fetchedAt)
}

// fetchGeolocationPins gets the observed pin set from the server and validates
// it, returning the map providertunnel.Config.Pins takes.
//
// This is the ONLY path from the server's answer into a pin set the prober will
// use, and it is a gate rather than a filter: an answer that does not cover
// every host in geolocate.SourceHosts() is an error, not a smaller set. That
// distinction is the entire lesson of the outage this replaced. A pin that
// fails is invisible in the result -- providertunnel refuses the host, the
// source drops out, and the fleet reports "no_consensus", which is
// indistinguishable from "fewer sources answered". Logging a warning and
// carrying on with the hosts that did arrive would reproduce exactly that, with
// the added twist that checkPin returns nil for a host absent from the map: the
// missing source would not merely be unavailable, it would be probed UNPINNED.
func fetchGeolocationPins(ctx context.Context, client *ingest.Client) (map[string][]string, error) {
	served, err := client.GeolocationPins(ctx)
	if err != nil {
		return nil, err
	}
	return validateGeolocationPins(served)
}

// validateGeolocationPins turns the served set into the prober's pin map, or
// refuses.
//
// It refuses when: a host in geolocate.SourceHosts() is absent from the served
// set, or its leaf or intermediate is empty (half a pin is not a pin, and the
// server never writes an empty one -- see the observation job, which errors
// rather than storing a chain it could not take an issuer from), or there are
// no source hosts at all.
//
// Hosts the server serves that are NOT geolocation sources are dropped, with a
// log line. Nothing dials them, so they are dead weight -- but the map is also
// providertunnel's allowlist of pinned hosts, and a set fetched over the
// network must not be able to widen it. This is the direction that costs
// nothing to be strict about: the dangerous drift (a source with no pin) is the
// one that raises.
func validateGeolocationPins(served map[string]ingest.GeolocationPin) (map[string][]string, error) {
	return fleetprobe.ValidateGeolocationPins(served)
}

// refreshGeolocationPins re-fetches the pin set once pinRefreshInterval has
// elapsed since the last SUCCESSFUL fetch.
//
// A failure here keeps the previous set and logs; it never clears it, never
// substitutes an empty map, and never returns an error the caller could mistake
// for "carry on unpinned". The startup fetch in main is the one that refuses to
// continue -- deliberately a different call site, because the two must never be
// one parameter apart.
//
// Keeping a stale set is the right trade and not merely the convenient one: the
// pins were observed by the server on a direct WebPKI-validated connection, so
// an old one still rejects a provider substituting its own certificate. What it
// eventually stops doing is matching the legitimate host after a CA change --
// which fails closed, loudly, in the same place a fresh set would.
func refreshGeolocationPins(ctx context.Context, client *ingest.Client, pins *pinSet, pinRefreshInterval time.Duration) {
	if pins.age() < pinRefreshInterval {
		return
	}
	refreshed, err := fetchGeolocationPins(ctx, client)
	if err != nil {
		log.Printf("egress-prober: geolocation pin refresh failed, keeping the set fetched %s ago (NOT degrading to unpinned): %s", pins.age().Round(time.Second), err)
		return
	}
	pins.set(refreshed)
}

// sortedHosts is the host list of a validated pin map, for a stable log line.
func sortedHosts(pins map[string][]string) []string {
	out := make([]string, 0, len(pins))
	for host := range pins {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// sortedServedHosts is the same for the raw served set, used in the error that
// names what the server DID send -- an operator diagnosing a missing host needs
// to see the other side of the comparison.
func sortedServedHosts(served map[string]ingest.GeolocationPin) []string {
	out := make([]string, 0, len(served))
	for host := range served {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// findProvidersCountPerLocation is the count requested in each per-location
// find-providers2 call. It is intentionally high: the server's selection
// (model.FindProviders2) weighted-shuffles and then truncates to `count`
// (`clientIds[:min(count, len(clientIds))]`), so a count well above any
// single location's real provider population effectively returns all of
// them, not a sample -- which is the whole point of I1 (a stable, complete
// enumeration, not a moving subset).
const findProvidersCountPerLocation = 5000

// listProviders enumerates every provider client id the server currently
// knows about, broadly and stably. This directly fixes I1: the previous
// implementation asked for `{"best_available":true}`, which on the server
// resolves to `countryCodeLocationIds()["us"]` (model.FindProviders2 in
// model/network_client_location_model.go) -- so it only ever enumerated
// providers the server's OWN geo database already believes are in the US.
// That is backwards for a tool whose entire purpose is finding providers
// whose location the database gets wrong. It was also
// weighted-random-sampled and shuffled server-side, so successive passes
// returned different subsets rather than a stable enumeration.
//
// The fix enumerates by location instead of by (wrong) assumption:
//  1. GET /network/provider-locations -- no auth required
//     (router.WrapNoAuth in the server's
//     api/handlers/network_client_location_handlers.go) -- which returns
//     every location, at every granularity (city/region/country) that
//     currently has at least one provider (model.GetProviderLocations,
//     filtered to locations present in loadLocationStables). Verified
//     against the server source at api/api.go and
//     model/network_client_location_model.go: the response is a
//     model.FindLocationsResult, whose `locations` field is
//     []*model.LocationResult with `location_id` (model.LocationResult).
//  2. For each returned location, POST /network/find-providers2 with an
//     explicit `{"specs":[{"location_id":"<id>"}],"count":<high>}` spec
//     (model.FindProviders2Args / model.ProviderSpec), and union the
//     `client_id`s (model.FindProvidersProvider) across all locations,
//     de-duplicating. A single provider legitimately appears under more
//     than one location (its city, region, and country entries each
//     resolve back to it -- confirmed by how the server populates its
//     per-location score cache in model.go's export path), so
//     de-duplication here is expected, not defensive overkill.
//
// Resilient by design: if one location's find-providers2 call fails
// (timeout, transient 5xx), it is logged and skipped rather than aborting
// the whole pass -- a broad enumeration that misses one location out of
// what can be hundreds is far more useful than a pass that produces
// nothing because one of them hiccupped.
func listProviders(ctx context.Context, apiURL string, byJwt string) ([]string, error) {
	httpClient := controlplane.NewHTTPClient(30 * time.Second)

	locationIds, err := listProviderLocationIds(ctx, httpClient, apiURL)
	if err != nil {
		return nil, fmt.Errorf("list provider locations: %w", err)
	}

	seen := make(map[string]struct{})
	succeeded := 0
	var lastErr error
	for _, locationId := range locationIds {
		clientIds, err := findProvidersAtLocation(ctx, httpClient, apiURL, byJwt, locationId)
		if err != nil {
			log.Printf("egress-prober: find-providers2 for location %s: %s (skipping this location for this pass)", locationId, err)
			lastErr = err
			continue
		}
		succeeded++
		for _, id := range clientIds {
			seen[id] = struct{}{}
		}
	}
	// Skipping SOME locations is resilience; skipping ALL of them is a
	// failed enumeration wearing a success return. The two endpoints can
	// genuinely diverge -- provider-locations is unauthenticated GET,
	// find-providers2 is an authenticated POST -- and an empty nil-error
	// result here flows into the "nothing to do (no providers, no failures)"
	// exit-0 path, which the exit-code contract explicitly promises an
	// external cron will never see from a pass that accomplished nothing.
	if len(locationIds) > 0 && succeeded == 0 {
		return nil, fmt.Errorf("find-providers2 failed for all %d locations (last: %w)", len(locationIds), lastErr)
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids, nil
}

// listProviderLocationIds calls GET /network/provider-locations and returns
// the location_id of every location in the response. See listProviders for
// the full rationale and the server-side source verified against.
func listProviderLocationIds(ctx context.Context, client *http.Client, apiURL string) ([]string, error) {
	url := strings.TrimRight(apiURL, "/") + "/network/provider-locations"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// Mirrors model.FindLocationsResult / model.LocationResult
	// (model/network_client_location_model.go) exactly: only the fields
	// this CLI actually needs are decoded.
	var out struct {
		Locations []struct {
			LocationId string `json:"location_id"`
		} `json:"locations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(out.Locations))
	for _, l := range out.Locations {
		ids = append(ids, l.LocationId)
	}
	return ids, nil
}

// findProvidersAtLocation calls POST /network/find-providers2 with a
// single explicit location_id spec and returns the client_id of every
// provider returned for it. See listProviders for the full rationale and
// the server-side source verified against.
func findProvidersAtLocation(ctx context.Context, client *http.Client, apiURL string, byJwt string, locationId string) ([]string, error) {
	// Mirrors model.FindProviders2Args / model.ProviderSpec
	// (model/network_client_location_model.go) exactly: Specs is
	// []*ProviderSpec, here a single spec with only LocationId set (json
	// "location_id"); Count and RankMode (json "rank_mode") match the
	// struct's json tags.
	//
	// ForceMinimum bypasses the PassesMinimums filter in loadClientScores.
	// That filter exists to keep low-quality providers out of user-facing
	// selection; a geolocation census wants every provider that can accept a
	// contract, so leaving it off returned 1 of 39 providers on beta.
	reqBody, err := json.Marshal(struct {
		Specs        []map[string]string `json:"specs"`
		Count        int                 `json:"count"`
		RankMode     string              `json:"rank_mode"`
		ForceMinimum bool                `json:"force_minimum"`
	}{
		Specs:        []map[string]string{{"location_id": locationId}},
		Count:        findProvidersCountPerLocation,
		RankMode:     "quality",
		ForceMinimum: true,
	})
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(apiURL, "/") + "/network/find-providers2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// find-providers2 does not require auth (router.WrapWithInputNoAuth on
	// the server), but the byJwt is sent anyway, matching the previous
	// implementation and every other call this CLI makes -- harmless, and
	// keeps this call consistent with the rest of the CLI's requests should
	// that ever change.
	req.Header.Set("Authorization", "Bearer "+byJwt)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// Mirrors model.FindProviders2Result / model.FindProvidersProvider
	// exactly: only client_id is decoded.
	var out struct {
		Providers []struct {
			ClientId string `json:"client_id"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(out.Providers))
	for _, p := range out.Providers {
		ids = append(ids, p.ClientId)
	}
	return ids, nil
}

// parseByJwtClientId extracts the client_id claim from byJwt and parses it as
// a connect.Id. This mirrors the proven implementation in
// urnetwork/proxy/socks/main.go:parseByJwtClientId: the jwt is parsed
// unverified (the prober is not the one who issued it; the server it talks to
// is the authority that already validated it when minting a session from it),
// and the claim is type-switched rather than unmarshaled into a typed struct,
// since some issuers emit client_id as something other than a bare string.
// errCredentialRejected reports that the server refused the prober's byJwt.
//
// This is kept distinct from "could not check" for the same reason
// ingest.ErrUnauthorized is kept distinct from ingest.ErrDueUnsupported: a
// rejected credential is a broken deployment, and anything that lets it look
// like an ordinary runtime hiccup hides the fault behind work that appears to
// continue.
var errCredentialRejected = errors.New("egress-prober: the server rejected the prober's byJwt")

// errCredentialUnverified reports that the check could not reach a verdict --
// an old server without the endpoint, a transport error, a 5xx. It is NOT a
// claim that the credential is bad, so it must never stop the prober: doing so
// would turn "we could not ask" into a new outage of its own.
var errCredentialUnverified = errors.New("egress-prober: could not verify the byJwt")

// checkCredential asks the server whether it ACCEPTS the byJwt, which is not
// what parseByJwtClientId establishes -- that only proves the token decodes and
// carries a client_id.
//
// The gap between those two is a real outage mode, not a hypothetical. A token
// that parses perfectly is still refused once it expires (jwt.expiryDuration is
// 24h) or once the server begins enforcing a claim the token predates, and the
// prober has no way to notice: the byJwt authenticates only the provider
// tunnel, while the due queue, attempt reporting and pin fetch all authenticate
// with the operator secret. So every one of those keeps working, the prober
// goes on reporting attempts and looks healthy, and the tunnel silently carries
// nothing -- every probe fails no_consensus with ok=0/N.
//
// That reads as "the whole fleet is bad", which is a convincing wrong answer.
// On one deployment it ran 8 hours and 870 consecutive failures before the
// credential was suspected. One request at startup turns that into a message.
func checkCredential(ctx context.Context, client *http.Client, apiURL string, byJwt string) error {
	url := strings.TrimRight(apiURL, "/") + "/network/clients"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errCredentialUnverified, err)
	}
	req.Header.Set("Authorization", "Bearer "+byJwt)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errCredentialUnverified, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return errCredentialRejected
	default:
		// Everything else -- notably 404 from a server that predates this
		// endpoint -- is inconclusive by design.
		return fmt.Errorf("%w: status %d", errCredentialUnverified, resp.StatusCode)
	}
}

func parseByJwtClientId(byJwt string) (connect.Id, error) {
	claims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(byJwt, claims); err != nil {
		return connect.Id{}, fmt.Errorf("parse jwt: %w", err)
	}

	jwtClientId, ok := claims["client_id"]
	if !ok {
		return connect.Id{}, fmt.Errorf("byJwt does not contain claim client_id")
	}
	switch v := jwtClientId.(type) {
	case string:
		return connect.ParseId(v)
	default:
		return connect.Id{}, fmt.Errorf("byJwt has invalid type for client_id: %T", v)
	}
}
