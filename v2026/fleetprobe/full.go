// Package fleetprobe composes the reusable one-pass provider probes. Process
// lifetime and scheduling belong to callers: the standalone command may loop,
// while the server taskworker runs one bounded batch and persists its successor.
package fleetprobe

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/urnetwork/connect/v2026"

	"github.com/urnetwork/operator-proxy/v2026/bandwidth"
	"github.com/urnetwork/operator-proxy/v2026/egresshealth"
	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/prober"
	"github.com/urnetwork/operator-proxy/v2026/providertunnel"
)

// PinSource returns the current complete certificate-pin set. Long-lived
// commands can refresh it between calls; a task normally supplies one snapshot.
type PinSource func() map[string][]string

// FullOptions holds everything needed for one full location/health pass.
// Each network dependency is explicit so tests can substitute it without a
// provider, and a task can remain a small scheduling adapter.
type FullOptions struct {
	TunnelConfig    providertunnel.Config
	Pins            PinSource
	ProbeTimeout    time.Duration
	Concurrency     int
	AllDestinations bool
	Submit          prober.Submitter
	Attempts        prober.AttemptReporter
	HealthResults   prober.HealthReporter
	Bandwidth       *bandwidth.Sampler
	BandwidthHosts  []string
}

// validateFullOptions rejects configurations that would hang a worker pool or
// turn every provider in a batch into the same synthetic failure.
// Required dependencies and bounds fail before a provider tunnel is opened.
func validateFullOptions(options FullOptions) error {
	if options.Pins == nil || len(options.Pins()) == 0 {
		return providertunnel.ErrPinsRequired
	}
	if options.ProbeTimeout <= 0 {
		return fmt.Errorf("fleetprobe: probe timeout must be positive (got %s)", options.ProbeTimeout)
	}
	if options.Concurrency < 1 {
		return fmt.Errorf("fleetprobe: concurrency must be positive (got %d)", options.Concurrency)
	}
	if options.Submit == nil {
		return fmt.Errorf("fleetprobe: location submitter is required")
	}
	if options.Attempts == nil {
		return fmt.Errorf("fleetprobe: attempt reporter is required")
	}
	return nil
}

// NewFullProber wires one tunnel per provider and runs every measurement over
// that same tunnel. Callers that need validation and bounded scheduling should
// normally use RunFull.
func NewFullProber(options FullOptions) *prober.Prober {
	extraHosts := append(egresshealth.DestinationHosts(), options.BandwidthHosts...)

	providerProber := &prober.Prober{
		Open: func(ctx context.Context, providerClientId string) (*http.Client, func() error, error) {
			clientId, err := connect.ParseId(providerClientId)
			if err != nil {
				return nil, nil, err
			}
			tunnelConfig := options.TunnelConfig
			tunnelConfig.Pins = options.Pins()
			tunnel, err := providertunnel.Open(ctx, tunnelConfig, clientId)
			if err != nil {
				return nil, nil, err
			}
			return tunnel.HTTPClientForHosts(options.ProbeTimeout, extraHosts), tunnel.Close, nil
		},
		Locate: func(ctx context.Context, client *http.Client) (*geolocate.ConsensusLocation, error) {
			return geolocate.LocateWithOptions(ctx, client, geolocate.LocateOptions{
				PerSourceTimeout: options.ProbeTimeout,
			})
		},
		Health: func(ctx context.Context, client *http.Client) (*egresshealth.Result, error) {
			return egresshealth.Check(ctx, client, EgressHealthOptions(options.ProbeTimeout, options.AllDestinations))
		},
		Submit:        options.Submit,
		Attempts:      options.Attempts,
		HealthResults: options.HealthResults,
	}

	if options.Bandwidth != nil {
		providerProber.Bandwidth = func(ctx context.Context, providerClientId string, client *http.Client) {
			results := options.Bandwidth.Sample(ctx, providerClientId, client)
			log.Printf("bandwidth: provider=%s %s", providerClientId, bandwidth.Summary(results))
		}
	}

	return providerProber
}

// RunFull executes one bounded batch. It owns no timer and schedules nothing;
// this is what lets a durable task checkpoint after every batch.
func RunFull(ctx context.Context, providerClientIds []string, options FullOptions) (prober.Summary, error) {
	if err := validateFullOptions(options); err != nil {
		return prober.Summary{}, err
	}
	scheduler := &prober.Scheduler{
		Prober:      NewFullProber(options),
		Concurrency: options.Concurrency,
		CacheTTL:    0,
	}
	return scheduler.Run(ctx, providerClientIds), nil
}

// EgressHealthRounds returns how many sequential request rounds one health
// run needs at its configured sampling geometry.
func EgressHealthRounds(allDestinations bool) int {
	requestCount := egresshealth.SamplePerRun()
	concurrency := egresshealth.DefaultConcurrency
	if allDestinations {
		requestCount = len(egresshealth.Destinations())
		concurrency = egresshealth.AllConcurrency
	}
	if rounds := (requestCount + concurrency - 1) / concurrency; 1 < rounds {
		return rounds
	}
	return 1
}

// EgressHealthOptions fits the whole health run inside one probe timeout.
func EgressHealthOptions(probeTimeout time.Duration, allDestinations bool) egresshealth.Options {
	rounds := EgressHealthRounds(allDestinations)
	concurrency := egresshealth.DefaultConcurrency
	if allDestinations {
		concurrency = egresshealth.AllConcurrency
	}
	perRequestTimeout := probeTimeout / time.Duration(rounds)
	if perRequestTimeout <= 0 {
		perRequestTimeout = probeTimeout
	}
	return egresshealth.Options{
		PerRequestTimeout: perRequestTimeout,
		Budget:            probeTimeout,
		AllDestinations:   allDestinations,
		Concurrency:       concurrency,
	}
}
