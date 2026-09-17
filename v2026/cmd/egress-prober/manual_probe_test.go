package main

// Manual, operator-driven probe of ONE named provider. Not part of the
// automated suite: it is skipped unless MANUAL_PROBE_PROVIDER is set, because
// it needs a live provider, a real network client jwt, and real egress.
//
// Build a runnable binary for a VPS with:
//
//	go test -c -o manualprobe ./cmd/egress-prober
//
// then run it there with MANUAL_PROBE_PROVIDER / UR_PROBER_BY_JWT set:
//
//	./manualprobe -test.run TestManualProbeOneProvider -test.v
//
// It prints what each geolocation source said individually alongside the
// consensus, so a disagreement between sources is visible rather than hidden
// behind the verdict, and then runs the egress-health check over the SAME
// tunnel and prints every destination's outcome. That second half is the
// end-to-end proof for the health signal: the same client, the same session,
// against every real destination the geolocation probe never touches.

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/urnetwork/connect/v2026"
	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
	"github.com/urnetwork/operator-proxy/v2026/providertunnel"
)

func TestManualProbeOneProvider(t *testing.T) {
	providerStr := os.Getenv("MANUAL_PROBE_PROVIDER")
	if providerStr == "" {
		t.Skip("set MANUAL_PROBE_PROVIDER to the provider client id to probe")
	}
	byJwt := os.Getenv("UR_PROBER_BY_JWT")
	apiURL := os.Getenv("MANUAL_PROBE_API_URL")
	platformURL := os.Getenv("MANUAL_PROBE_PLATFORM_URL")
	// The operator secret is required now that the pins come from the server:
	// this probe fetches the same set the CLI does, from the same endpoint,
	// with the same validation, so it keeps exercising the shipped path rather
	// than a permissive one of its own.
	operatorSecret := os.Getenv("UR_OPERATOR_SECRET")
	if byJwt == "" || apiURL == "" || platformURL == "" || operatorSecret == "" {
		t.Fatal("UR_PROBER_BY_JWT, UR_OPERATOR_SECRET, MANUAL_PROBE_API_URL and MANUAL_PROBE_PLATFORM_URL are all required")
	}

	providerId, err := connect.ParseId(providerStr)
	if err != nil {
		t.Fatalf("parse provider client id %q: %s", providerStr, err)
	}
	selfId, err := parseByJwtClientId(byJwt)
	if err != nil {
		t.Fatalf("parse by-jwt client id: %s", err)
	}

	// This one deadline bounds BOTH halves, so it has to cover the health
	// check's worst case as well as geolocation's: geolocation is three sources
	// in parallel at 45s, and the health run is
	// ceil(31 destinations / DefaultConcurrency 6) = 6 rounds x 45s = 4m30s.
	// Ten minutes leaves both room. A deadline that expired mid-run would cut
	// off the trailing destinations and print them as failures the provider had
	// nothing to do with -- in the one tool an operator uses to eyeball a single
	// provider by hand.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// The same pins the real CLI uses, fetched the same way: from the server's
	// observed set, through the same validation, which fails here rather than
	// probing unpinned if the server cannot cover every geolocation source.
	pins, err := fetchGeolocationPins(ctx, &ingest.Client{
		ServerURL:      apiURL,
		OperatorSecret: operatorSecret,
		HTTP:           &http.Client{Timeout: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("fetch the geolocation certificate pins from %s: %s", apiURL, err)
	}
	t.Logf("geolocation pins    %d host(s) from the server", len(pins))

	tun, err := providertunnel.Open(ctx, providertunnel.Config{
		ApiURL:            apiURL,
		PlatformURL:       platformURL,
		ByJwt:             byJwt,
		ClientId:          selfId,
		Pins:              pins,
		DeviceDescription: "manual egress probe",
		DeviceSpec:        "egress-prober",
		Version:           "0.0.0",
	}, providerId)
	if err != nil {
		t.Fatalf("open tunnel to provider %s: %s", providerId, err)
	}
	defer tun.Close()

	// The same one client the CLI builds: geolocation hosts pinned, egress
	// health destinations allowed unpinned. Using tun.HTTPClient here instead
	// would refuse every health destination at the allowlist, so this also
	// keeps the manual probe honest about what the shipped path does.
	client := tun.HTTPClientForHosts(90*time.Second, egresshealth.DestinationHosts())

	loc, err := geolocate.LocateWithOptions(ctx, client,
		geolocate.LocateOptions{PerSourceTimeout: 45 * time.Second})
	if err != nil {
		t.Fatalf("geolocate through provider %s: %s", providerId, err)
	}

	t.Logf("provider            %s", providerId)
	t.Logf("country             %s (%s) confident=%t", loc.Country, loc.CountryCode, loc.CountryConfident)
	t.Logf("city / region       %q / %q confident=%t", loc.City, loc.Region, loc.CityConfident)
	t.Logf("asn / org           %d / %s", loc.ASN, loc.Org)
	t.Logf("hosting/proxy/mobile %t/%t/%t", loc.Hosting, loc.Proxy, loc.Mobile)
	for _, s := range loc.Sources {
		if s.OK {
			t.Logf("  source %-12s ok   cc=%-4s city=%-18q region=%-16q asn=%-8d org=%s",
				s.Name, s.CountryCode, s.City, s.Region, s.ASN, s.Org)
		} else {
			t.Logf("  source %-12s FAIL %s", s.Name, s.Err)
		}
	}

	// Egress health over the SAME tunnel -- never a second one.
	//
	// Budget is rounds x PerRequestTimeout, the same arithmetic
	// egressHealthOptions holds for the shipped path: 6 rounds x 45s = 4m30s,
	// so 6 minutes fits with room. A 3-minute budget (what this carried while
	// the table held nine destinations and concurrency was 3) would now cut off
	// the last round every time. The per-request timeout stays deliberately
	// generous because this runs once, interactively, over a cold tunnel.
	health, err := egresshealth.Check(ctx, client, egresshealth.Options{
		PerRequestTimeout: 45 * time.Second,
		Budget:            6 * time.Minute,
	})
	if err != nil {
		t.Fatalf("egress health through provider %s did not run: %s", providerId, err)
	}
	t.Logf("egress-health       %s", health.Summary())
	for _, c := range health.Checks {
		status := "FAIL"
		if c.OK {
			status = "ok  "
		}
		t.Logf("  %-4s %-18s %-5s status=%-4d bytes=%-6d %-8s %s",
			status, c.Name, c.Class, c.StatusCode, c.ByteCount, c.Latency.Round(time.Millisecond), c.Err)
	}
}
