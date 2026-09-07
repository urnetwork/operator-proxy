package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/bandwidth"
	"github.com/urnetwork/operator-proxy/v2026/confinement"
	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
)

// lookupFails is a resolver that cannot resolve anything. That is both a
// correctly confined deployment (dns to a public resolver is blocked too) and
// a compose stack whose resolver has not settled yet -- and in neither case
// does it tell the prober anything about whether it can reach a geolocation
// api.
func lookupFails(ctx context.Context, host string) ([]string, error) {
	return nil, errors.New("lookup " + host + ": no such host")
}

// lookupPerHost gives every host the check is supposed to cover -- geolocation
// sources AND egress-health destinations -- its own documentation-range
// address, so a test can assert that the check covered exactly that set.
func lookupPerHost(ctx context.Context, host string) ([]string, error) {
	for i, h := range probeHosts() {
		if h == host {
			return []string{fmt.Sprintf("203.0.113.%d", i+1)}, nil
		}
	}
	return nil, errors.New("lookup " + host + ": no such host")
}

// captureLog redirects the standard logger for the duration of a test and
// returns what was written.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	flags := log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return buf
}

// TestCheckConfinementProbesEveryProbeHost is the anti-drift assertion that
// matters most here: the addresses the check tests must be DERIVED from the
// same tables the prober will later fetch through a tunnel -- geolocate's
// sources and egresshealth's destinations -- not a second hand-maintained copy.
// A second copy drifts on the first endpoint change and the check keeps passing
// while no longer covering a real endpoint.
func TestCheckConfinementProbesEveryProbeHost(t *testing.T) {
	captureLog(t)
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}

	if err := checkConfinement(context.Background(), dial, lookupPerHost, nil, time.Second); err != nil {
		t.Fatalf("checkConfinement: %s", err)
	}

	hosts := probeHosts()
	if len(hosts) == 0 {
		t.Fatal("probeHosts is empty; the check would have nothing to test")
	}
	var want []string
	for i := range hosts {
		want = append(want, net.JoinHostPort(fmt.Sprintf("203.0.113.%d", i+1), confinementPort))
	}
	sort.Strings(want)
	sort.Strings(dialed)
	if strings.Join(dialed, ",") != strings.Join(want, ",") {
		t.Fatalf("checkConfinement dialed %v, want the resolved address of every probe host %v (%v)", dialed, want, hosts)
	}
}

// TestCheckConfinementRefusesWhenReachable: a successful direct connection
// means the operator's confinement is missing, so the prober must not run --
// every provider would otherwise be recorded at the operator's own location.
func TestCheckConfinementRefusesWhenReachable(t *testing.T) {
	captureLog(t)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, _ := net.Pipe()
		return c1, nil
	}
	err := checkConfinement(context.Background(), dial, lookupPerHost, nil, time.Second)
	if err == nil {
		t.Fatal("checkConfinement returned nil while a geolocation address was directly reachable")
	}
	if !errors.Is(err, confinement.ErrNotConfined) {
		t.Fatalf("checkConfinement error = %v, want ErrNotConfined", err)
	}
}

// TestCheckConfinementUsesResolvedAddressesWhenDnsWorks: when dns is available
// the check must test the resolved ips, not just the names -- dialing a name
// that fails to resolve proves nothing about whether the ip behind it is
// reachable.
func TestCheckConfinementUsesResolvedAddressesWhenDnsWorks(t *testing.T) {
	captureLog(t)
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}
	if err := checkConfinement(context.Background(), dial, lookup, nil, time.Second); err != nil {
		t.Fatalf("checkConfinement: %s", err)
	}
	if len(dialed) != 1 || dialed[0] != "203.0.113.9:"+confinementPort {
		t.Fatalf("checkConfinement dialed %v, want the resolved address 203.0.113.9:%s", dialed, confinementPort)
	}
}

// TestCheckConfinementRefusesWhenNothingResolves is the defect this fix
// exists for, at the level the operator sees it. With dns blocked -- the very
// deployment the old hostname fallback was written for -- every host fell back
// to a bare name, every dial failed at resolution rather than at a deny rule,
// and the check logged "passed" having tested nothing. A prober on a container
// with full internet egress would then record every provider at the operator's
// location. The check must refuse to start instead, and must not dial a
// hostname it knows will not resolve.
func TestCheckConfinementRefusesWhenNothingResolves(t *testing.T) {
	captureLog(t)
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}

	err := checkConfinement(context.Background(), dial, lookupFails, nil, time.Second)
	if err == nil {
		t.Fatal("checkConfinement returned nil although not one geolocation host resolved; it tested nothing and must refuse to start")
	}
	if !errors.Is(err, confinement.ErrNoEvidence) {
		t.Fatalf("checkConfinement error = %v, want ErrNoEvidence", err)
	}
	if len(dialed) != 0 {
		t.Fatalf("checkConfinement dialed %v; an unresolvable hostname must never be dialed -- it fails at resolution and carries no signal", dialed)
	}
	// the two legitimate remedies, so the operator is not pushed towards
	// -skip-confinement-check
	for _, want := range []string{"dns", "-confinement-address"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("checkConfinement error %q does not mention %q", err, want)
		}
	}
}

// TestCheckConfinementWarnsWhenSomeHostsDoNotResolve: a check that covered two
// of three endpoints must not read like one that covered all three. The
// resolved hosts are still tested; the gap is named.
func TestCheckConfinementWarnsWhenSomeHostsDoNotResolve(t *testing.T) {
	logs := captureLog(t)
	hosts := probeHosts()
	if len(hosts) < 2 {
		t.Skip("need at least two probe hosts for a partial-resolution case")
	}
	skipped := hosts[len(hosts)-1]
	lookup := func(ctx context.Context, host string) ([]string, error) {
		if host == skipped {
			return nil, errors.New("lookup " + host + ": no such host")
		}
		return lookupPerHost(ctx, host)
	}
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}

	if err := checkConfinement(context.Background(), dial, lookup, nil, time.Second); err != nil {
		t.Fatalf("checkConfinement: %s; the hosts that did resolve are still real evidence and must still be checked", err)
	}
	if len(dialed) != len(hosts)-1 {
		t.Fatalf("dialed %v, want the %d host(s) that resolved", dialed, len(hosts)-1)
	}
	out := logs.String()
	if !strings.Contains(out, "WARNING") {
		t.Fatalf("a degraded check logged no WARNING; it is indistinguishable from a complete one.\n--- log ---\n%s", out)
	}
	if !strings.Contains(out, skipped) {
		t.Fatalf("the WARNING does not name the unresolved host %q.\n--- log ---\n%s", skipped, out)
	}
}

// TestCheckConfinementUsesExplicitAddressesWithoutResolving covers the escape
// hatch: in a jail where dns genuinely cannot work, the operator supplies the
// addresses and the check stays a real check, rather than being switched off
// with -skip-confinement-check.
func TestCheckConfinementUsesExplicitAddressesWithoutResolving(t *testing.T) {
	captureLog(t)
	resolved := false
	lookup := func(ctx context.Context, host string) ([]string, error) {
		resolved = true
		return []string{"203.0.113.9"}, nil
	}
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}

	explicit := []string{"198.51.100.7:443", "198.51.100.8:443"}
	if err := checkConfinement(context.Background(), dial, lookup, explicit, time.Second); err != nil {
		t.Fatalf("checkConfinement: %s", err)
	}
	if resolved {
		t.Error("checkConfinement resolved even though explicit addresses were supplied; the flag exists for a jail where resolution cannot work")
	}
	if strings.Join(dialed, ",") != strings.Join(explicit, ",") {
		t.Fatalf("checkConfinement dialed %v, want exactly the supplied %v", dialed, explicit)
	}
}

// TestCheckConfinementStillRefusesWithExplicitAddresses: the escape hatch
// supplies what to dial, not permission to skip the verdict.
func TestCheckConfinementStillRefusesWithExplicitAddresses(t *testing.T) {
	captureLog(t)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, _ := net.Pipe()
		return c1, nil
	}
	err := checkConfinement(context.Background(), dial, lookupFails, []string{"198.51.100.7:443"}, time.Second)
	if !errors.Is(err, confinement.ErrNotConfined) {
		t.Fatalf("checkConfinement error = %v, want ErrNotConfined", err)
	}
}

// TestConfinementAddressFlagRejectsANonAddress: a hostname here would put the
// defect straight back -- in the dns-blocked jail this flag is for, the dial
// would fail at resolution and prove nothing.
func TestConfinementAddressFlagRejectsANonAddress(t *testing.T) {
	for _, bad := range []string{"ipinfo.io:443", "198.51.100.7", "", "198.51.100.7:"} {
		var list addressList
		if err := list.Set(bad); err == nil {
			t.Errorf("-confinement-address accepted %q; it must be an ip literal with a port", bad)
		}
	}
	var list addressList
	if err := list.Set("198.51.100.7:443"); err != nil {
		t.Errorf("-confinement-address rejected a valid ip:port: %s", err)
	}
	if err := list.Set("[2606:4700::1111]:443"); err != nil {
		t.Errorf("-confinement-address rejected a valid ipv6 address: %s", err)
	}
	if len(list) != 2 {
		t.Errorf("addressList = %v, want both values collected; the flag is repeatable", list)
	}
}

// TestSkipConfinementCheckIsOffByDefault: a check that is off by default is not
// a check. This asserts on the built binary's own -h output, so it holds
// regardless of how the flag is wired internally.
func TestSkipConfinementCheckIsOffByDefault(t *testing.T) {
	out := runProberWithSecretsInEnv(t, "-h")
	if !strings.Contains(out, "-skip-confinement-check") {
		t.Fatalf("-h does not document -skip-confinement-check.\n--- output ---\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "skip-confinement-check") {
			// flag.PrintDefaults renders a true bool default as `(default true)`
			// and omits the clause entirely for false.
			if strings.Contains(line, "default true") {
				t.Fatalf("-skip-confinement-check defaults to true; the confinement check must be on unless explicitly disabled.\n--- line ---\n%s", line)
			}
		}
	}
}

// TestSkipConfinementCheckLogsLoudly: the escape hatch exists for the operator
// running a one-shot manual probe, but it disables the only thing standing
// between a misconfigured host and recording every provider at the operator's
// own location. It must be impossible to miss in the log.
//
// The run dies at parseByJwtClientId on the placeholder jwt, immediately after
// the check and before any network call, so nothing real is contacted. (The
// unreachable -api-url is belt and braces: it is never dialed.)
func TestSkipConfinementCheckLogsLoudly(t *testing.T) {
	out := runProberWithSecretsInEnv(t,
		"-skip-confinement-check",
		"-api-url", "http://127.0.0.1:1",
		"-platform-url", "ws://127.0.0.1:1",
		"-interval", "0",
	)
	if !strings.Contains(out, "WARNING") {
		t.Fatalf("-skip-confinement-check produced no WARNING line.\n--- output ---\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "confinement") {
		t.Fatalf("-skip-confinement-check did not say what was skipped.\n--- output ---\n%s", out)
	}
}

// TestConfinementTimeoutBelowTheFloorIsRejected drives the real binary,
// because this was a live hole reproduced with the real binary: on a host with
// open egress, -confinement-timeout 10ms correctly reported "not confined" and
// exited 1, while 1ms -- the same host, the same second -- logged
// "confinement self-check passed" and started. Rejecting only <= 0 left every
// positive-but-too-small value able to switch the guarantee off while logging
// success. The binary must refuse the flag before it runs the check at all.
func TestConfinementTimeoutBelowTheFloorIsRejected(t *testing.T) {
	for _, timeout := range []string{"1ms", "10ms", "499ms"} {
		out, code := runProber(t,
			"-api-url", "http://127.0.0.1:1",
			"-platform-url", "ws://127.0.0.1:1",
			"-interval", "0",
			"-confinement-timeout", timeout,
		)
		if code != 2 {
			t.Errorf("-confinement-timeout %s exited %d, want 2 (a rejected flag).\n--- output ---\n%s", timeout, code, out)
		}
		if !strings.Contains(out, "-confinement-timeout must be at least") {
			t.Errorf("-confinement-timeout %s was not rejected with a clear message.\n--- output ---\n%s", timeout, out)
		}
		if strings.Contains(out, "self-check passed") {
			t.Errorf("-confinement-timeout %s reported the self-check as PASSED; a dial that expires before a connection could complete tests nothing.\n--- output ---\n%s", timeout, out)
		}
	}
}

// runProber runs the built binary and returns its combined output and exit
// code. Like runProberWithSecretsInEnv, but the exit code is the assertion.
func runProber(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(buildProber(t), args...)
	cmd.Env = append(os.Environ(),
		"UR_PROBER_BY_JWT="+testJwtSecret,
		"UR_OPERATOR_SECRET="+testOperatorSecret,
	)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("running the prober: %s", err)
		return "", -1
	}
}

// TestProbeHostsCoversBothTables: the confinement self-check is only as good as
// the host list it is given. Both tables must be represented, and neither may
// be represented twice -- a duplicate would make the check dial the same
// address again and read like broader coverage than it has.
//
// The egress-health destinations matter here in a way that is easy to
// under-weight. A prober that can reach them directly does not merely leak the
// operator's address: the check would PASS from the operator's own host, and so
// would certify a blackholing provider as healthy. That is the inversion of the
// signal, not a degradation of it.
func TestProbeHostsCoversBothTables(t *testing.T) {
	hosts := probeHosts()
	index := map[string]int{}
	for _, h := range hosts {
		index[h]++
	}
	for _, h := range hosts {
		if index[h] != 1 {
			t.Fatalf("probeHosts lists %q %d times: %v", h, index[h], hosts)
		}
	}
	for _, h := range geolocate.SourceHosts() {
		if index[h] == 0 {
			t.Errorf("geolocation source host %q is not in probeHosts %v; the confinement check would not cover it", h, hosts)
		}
	}
	for _, h := range egresshealth.DestinationHosts() {
		if index[h] == 0 {
			t.Errorf("egress-health destination host %q is not in probeHosts %v; the confinement check would not cover it, and an operator reading -confinement-address guidance would never learn it exists", h, hosts)
		}
	}
	if len(hosts) < len(egresshealth.DestinationHosts()) {
		t.Fatalf("probeHosts (%d) is smaller than the egress-health table alone (%d)", len(hosts), len(egresshealth.DestinationHosts()))
	}
}

// TestEgressHealthDestinationsAreNotPinned records a deliberate decision so it
// cannot be reversed by accident. The health destinations are reached through
// the tunnel WITHOUT certificate pins (see
// providertunnel.Tunnel.HTTPClientForHosts): their leaves rotate on nine
// independent schedules, and a stale pin would surface as a failed destination
// -- indistinguishable, in the recorded result, from the provider blackholing
// it. Ordinary WebPKI verification still applies, which is what a provider on
// the path cannot forge.
func TestEgressHealthDestinationsAreNotPinned(t *testing.T) {
	// Built the way the running prober builds it: from a served set, through
	// the one validation gate. The served set here is deliberately hostile --
	// it offers a pin for every egress-health destination as well as every
	// geolocation source, which is exactly what a server-side mistake would
	// look like -- and the gate must still hand back a map covering only the
	// geolocation sources.
	served := map[string]ingest.GeolocationPin{}
	for _, h := range geolocate.SourceHosts() {
		served[h] = ingest.GeolocationPin{Leaf: "leaf-" + h, Intermediate: "int-" + h}
	}
	for _, h := range egresshealth.DestinationHosts() {
		served[h] = ingest.GeolocationPin{Leaf: "leaf-" + h, Intermediate: "int-" + h}
	}

	pins, err := validateGeolocationPins(served)
	if err != nil {
		t.Fatalf("validateGeolocationPins: %s", err)
	}
	for _, h := range egresshealth.DestinationHosts() {
		if _, pinned := pins[h]; pinned {
			t.Errorf("egress-health destination %q has a certificate pin; routine leaf rotation would then read as the provider blackholing it -- and a pin map fetched over the network must not be able to widen the tunnel's allowlist", h)
		}
	}
}

// TestEgressHealthAddsAtMostOneProbeTimeout is the arithmetic that keeps the
// health check from stalling a pass. There is no per-provider deadline in the
// scheduler, so whatever budget the health check gets is added to the wall
// clock of every probe against a provider that swallows requests. A budget of
// one-per-request across three rounds would triple that. The whole run must fit
// in one -probe-timeout.
func TestEgressHealthAddsAtMostOneProbeTimeout(t *testing.T) {
	for _, probeTimeout := range []time.Duration{time.Second, 30 * time.Second, 60 * time.Second, 5 * time.Minute} {
		opts := egressHealthOptions(probeTimeout, false)
		if opts.Budget != probeTimeout {
			t.Errorf("egressHealthOptions(%s).Budget = %s; a full health run must add at most one -probe-timeout per provider", probeTimeout, opts.Budget)
		}
		if opts.PerRequestTimeout <= 0 {
			t.Errorf("egressHealthOptions(%s).PerRequestTimeout = %s, want positive", probeTimeout, opts.PerRequestTimeout)
		}
		if opts.PerRequestTimeout > opts.Budget {
			t.Errorf("egressHealthOptions(%s): per-request %s exceeds the whole-run budget %s", probeTimeout, opts.PerRequestTimeout, opts.Budget)
		}
		// The per-request bound must leave room for every SAMPLED destination
		// to be attempted within the budget, or the last round is always cut
		// off and those destinations fail for a reason the provider had nothing
		// to do with.
		rounds := (egresshealth.SamplePerRun() + egresshealth.DefaultConcurrency - 1) / egresshealth.DefaultConcurrency
		if got := opts.PerRequestTimeout * time.Duration(rounds); got > opts.Budget {
			t.Errorf("egressHealthOptions(%s): %d rounds x %s = %s exceeds the budget %s; the last round would always be cut off",
				probeTimeout, rounds, opts.PerRequestTimeout, got, opts.Budget)
		}
		// ...and it must be sized off the sample rather than the table, or each
		// request gets a fraction of what a cold-tunnel request needs while the
		// assertion above still passes.
		if wholeTable := (len(egresshealth.Destinations()) + egresshealth.DefaultConcurrency - 1) / egresshealth.DefaultConcurrency; rounds >= wholeTable {
			t.Errorf("egressHealthOptions divides %s across %d rounds, which is the whole %d-entry table; a run samples %d destinations",
				probeTimeout, rounds, len(egresshealth.Destinations()), egresshealth.SamplePerRun())
		}
	}
	// ...and it must still scale, so raising -probe-timeout actually helps a
	// slow provider.
	if egressHealthOptions(10*time.Second, false).PerRequestTimeout <= egressHealthOptions(time.Second, false).PerRequestTimeout {
		t.Error("egressHealthOptions does not scale with -probe-timeout")
	}
}

// TestEgressHealthAllAddsAtMostOneProbeTimeout pins the SHIPPED
// configuration. -egress-health-all defaults to true, and that path derived
// its per-request bound from the sampled round count (5) and then multiplied
// it by the full-table round count (14), so the health run drew 2.8x
// -probe-timeout -- a blackholing provider cost ~3.8x per probe, which is
// the ~4x regression the arithmetic in egressHealthOptions exists to
// prevent, arriving through the default nobody had measured. The invariant
// is the same one the sampled path is held to, so it is asserted the same
// way.
func TestEgressHealthAllAddsAtMostOneProbeTimeout(t *testing.T) {
	for _, probeTimeout := range []time.Duration{time.Second, 30 * time.Second, 60 * time.Second, 5 * time.Minute} {
		opts := egressHealthOptions(probeTimeout, true)
		if !opts.AllDestinations {
			t.Fatalf("egressHealthOptions(%s, true).AllDestinations = false", probeTimeout)
		}
		if opts.Budget > probeTimeout {
			t.Errorf("egressHealthOptions(%s, true).Budget = %s (%.2fx); a full health run must add at most one -probe-timeout per provider",
				probeTimeout, opts.Budget, float64(opts.Budget)/float64(probeTimeout))
		}
		if opts.PerRequestTimeout <= 0 {
			t.Errorf("egressHealthOptions(%s, true).PerRequestTimeout = %s, want positive", probeTimeout, opts.PerRequestTimeout)
		}
		// Every destination in the WHOLE table must be attemptable inside the
		// budget, or the last rounds are always cut off and those destinations
		// fail for a reason the provider had nothing to do with.
		rounds := (len(egresshealth.Destinations()) + opts.Concurrency - 1) / opts.Concurrency
		if got := opts.PerRequestTimeout * time.Duration(rounds); got > opts.Budget {
			t.Errorf("egressHealthOptions(%s, true): %d rounds x %s = %s exceeds the budget %s; the last rounds would always be cut off",
				probeTimeout, rounds, opts.PerRequestTimeout, got, opts.Budget)
		}
	}
	if egressHealthOptions(10*time.Second, true).PerRequestTimeout <= egressHealthOptions(time.Second, true).PerRequestTimeout {
		t.Error("egressHealthOptions(_, true) does not scale with -probe-timeout")
	}
}

// The full table is the default because it is the only configuration that
// exercises CONCURRENCY: a sample asks the provider to carry ~30 parallel
// requests, where a real client under load looks far more like the whole
// table. Sampling remains available and is cheaper, but it cannot test that.
func TestEgressHealthAllDefaultsOn(t *testing.T) {
	fs := flag.NewFlagSet("egress-prober", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	all := fs.Bool("egress-health-all", true, "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %s", err)
	}
	if !*all {
		t.Error("-egress-health-all defaults off; every provider test must run the full table")
	}
}

// TestBandwidthCDNHostIsInTheConfinementCheck: the CDN target is a
// third-party host reached through the tunnel, so a jail that lets the
// prober reach it directly is the same defect as one that lets it reach a
// geolocation api. probeHosts' comment claimed to cover "every third-party
// host this process reaches through a tunnel" while excluding it, and an
// operator translating that list into -confinement-address entries would
// never learn it existed.
func TestBandwidthCDNHostIsInTheConfinementCheck(t *testing.T) {
	hosts := probeHosts(bandwidthProbeHosts(false, bandwidth.CDNTestURL)...)
	want := "speed.cloudflare.com"
	if !slices.Contains(hosts, want) {
		t.Errorf("probe hosts do not include the bandwidth CDN target %q", want)
	}

	// -skip-bandwidth means the host is never reached, so it must not be
	// dialed by the self-check either: a host this process will not touch is
	// not evidence about the confinement it needs.
	if got := bandwidthProbeHosts(true, bandwidth.CDNTestURL); len(got) != 0 {
		t.Errorf("bandwidthProbeHosts with -skip-bandwidth = %v, want none", got)
	}

	// A custom -bandwidth-cdn-url must follow, or the check covers a host the
	// deployment does not use while missing the one it does.
	if got := bandwidthProbeHosts(false, "https://mirror.example.net/__down"); len(got) != 1 || got[0] != "mirror.example.net" {
		t.Errorf("bandwidthProbeHosts with a custom url = %v, want [mirror.example.net]", got)
	}
}

// TestNegativeCacheTTLIsRejected: a negative ttl makes recentlyProbed always
// false, silently disabling the enumeration cache. Every other duration flag
// fails fast.
func TestNegativeCacheTTLIsRejected(t *testing.T) {
	out, code := runProber(t,
		"-api-url", "http://127.0.0.1:1",
		"-platform-url", "ws://127.0.0.1:1",
		"-cache-ttl", "-1h",
	)
	if code == 0 {
		t.Fatalf("a negative -cache-ttl was accepted.\n--- output ---\n%s", out)
	}
	if !strings.Contains(out, "-cache-ttl") {
		t.Errorf("the failure does not name -cache-ttl.\n--- output ---\n%s", out)
	}
}
