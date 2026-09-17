package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/urnetwork/operator-proxy/v2026/fleetprobe"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
	"github.com/urnetwork/operator-proxy/v2026/providertunnel"
)

// blackholeSweeper runs the cheap liveness check across the whole fleet on its
// own cadence in the standalone command. Server deployments use the same
// fleetprobe pass from recurring taskworker shards instead.
type blackholeSweeper struct {
	operator    *ingest.Client
	tunnelCfg   providertunnel.Config
	pins        *pinSet
	timeout     time.Duration
	concurrency int
	limit       int
	// checkOneFn is the deterministic test seam for the bounded worker pool.
	// Production leaves it nil and fleetprobe opens the real tunnel.
	checkOneFn func(context.Context, string) blackholeResult
}

// Forty rounds times the server's 5000 ceiling is above a real fleet. The cap
// prevents a misbehaving due endpoint from holding one command pass forever.
const maxBlackholeRounds = 40

type blackholeResult struct {
	check   ingest.BlackholeCheck
	dark    bool
	tunnel  bool
	details string
}

// sweep asks what is due, runs one fixed-worker-pool batch, and submits the
// whole result atomically.
func (self *blackholeSweeper) sweep(ctx context.Context) (checked int, err error) {
	providerClientIds, err := self.operator.BlackholeDue(ctx, self.limit)
	if err != nil {
		return 0, err
	}
	if len(providerClientIds) == 0 {
		return 0, nil
	}

	var checker fleetprobe.BlackholeChecker
	if self.checkOneFn != nil {
		checker = func(ctx context.Context, providerClientId string) fleetprobe.BlackholeResult {
			result := self.checkOneFn(ctx, providerClientId)
			return fleetprobe.BlackholeResult{
				Check:        result.check,
				Dark:         result.dark,
				TunnelFailed: result.tunnel,
				Details:      result.details,
			}
		}
	}
	summary, err := fleetprobe.RunBlackhole(ctx, providerClientIds, fleetprobe.BlackholeOptions{
		TunnelConfig: self.tunnelCfg,
		Pins:         self.pins.get,
		Timeout:      self.timeout,
		Concurrency:  self.concurrency,
		CheckOne:     checker,
	})
	if err != nil {
		return 0, err
	}
	if len(summary.Checks) == 0 {
		return 0, nil
	}
	if err := self.operator.SubmitBlackholeChecks(ctx, summary.Checks); err != nil {
		return 0, fmt.Errorf("submitting %d checks: %w", len(summary.Checks), err)
	}

	log.Printf(
		"blackhole: pass checked=%d dark=%d (tunnel_failed=%d) ok=%d",
		len(summary.Checks),
		summary.Dark,
		summary.TunnelFailed,
		len(summary.Checks)-summary.Dark,
	)
	return len(summary.Checks), nil
}

// run repeats complete bounded sweeps until cancellation. Taskworker mode does
// not use this loop; its durable post-step owns repetition instead.
func (self *blackholeSweeper) run(ctx context.Context, interval time.Duration) {
	for {
		start := time.Now()
		total := 0
		var err error
		for range maxBlackholeRounds {
			var checked int
			checked, err = self.sweep(ctx)
			total += checked
			if err != nil || checked == 0 || ctx.Err() != nil {
				break
			}
		}
		switch {
		case err == nil:
			if total == 0 {
				log.Printf("blackhole: pass found nothing due")
			} else {
				log.Printf("blackhole: sweep complete: %d checked in %s", total, time.Since(start).Round(time.Second))
			}
		case errors.Is(err, ingest.ErrBlackholeUnsupported):
			log.Printf("blackhole: the server does not implement the blackhole endpoints; sweeping is disabled")
			return
		case errors.Is(err, ingest.ErrUnauthorized):
			log.Printf("blackhole: the server rejected the operator secret; sweeping is disabled. Fix -operator-secret and restart.")
			return
		default:
			log.Printf("blackhole: pass failed after %s: %s", time.Since(start).Round(time.Second), err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
