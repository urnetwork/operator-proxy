package prober

import (
	"context"
	"log"
	"sync"
	"time"
)

// maxLoggedDistinctErrors caps how many DISTINCT probe error messages are
// logged in detail during a single Run (I2). Without a cap, a pass where
// every provider fails the same way (a wrong -platform-url, a revoked jwt)
// would flood the log with the same message hundreds of times, drowning
// out anything that could distinguish it from a handful of unrelated
// failures. 10 is chosen as "enough to see the shape of what's failing
// (one pin mismatch, one auth error, a few dial timeouts) without a flood";
// Run still logs a one-line notice once the cap is hit, and the pass's
// total Failed count is always visible via the Summary the caller logs.
const maxLoggedDistinctErrors = 10

// Summary reports one scheduler run.
type Summary struct {
	Attempted int
	Submitted int
	Skipped   int
	Failed    int
}

// Scheduler probes a set of providers with bounded concurrency, skipping any
// provider probed within CacheTTL. Only successful probes are cached, so a
// failure is retried on the next run.
type Scheduler struct {
	Prober      *Prober
	Concurrency int
	CacheTTL    time.Duration
	// Now defaults to time.Now; tests override it to advance the clock.
	Now func() time.Time

	mu     sync.Mutex
	probed map[string]time.Time
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) recentlyProbed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.probed[id]
	if !ok {
		return false
	}
	return s.now().Sub(last) < s.CacheTTL
}

func (s *Scheduler) markProbed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probed == nil {
		s.probed = map[string]time.Time{}
	}
	s.probed[id] = s.now()
}

// prune evicts entries from probed older than CacheTTL (M2). Without this,
// probed only ever grows: markProbed adds an entry per successfully probed
// provider and nothing ever removed one, so a long-lived process (this
// scheduler is driven from an infinite loop in cmd/egress-prober) would
// accumulate one map entry per provider ever seen, forever. An entry past
// CacheTTL no longer affects recentlyProbed's decision anyway (its age
// already exceeds the cache window), so evicting it changes no behavior --
// it only bounds memory. Pruning is O(n) over probed and runs once per Run
// call, which is cheap relative to the network calls Run is about to make.
func (s *Scheduler) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probed == nil {
		return
	}
	now := s.now()
	for id, last := range s.probed {
		if s.CacheTTL <= now.Sub(last) {
			delete(s.probed, id)
		}
	}
}

// Run probes each provider that is not cached, with at most Concurrency
// tunnels open at once.
//
// Per-provider failures are logged as they occur (I2): before this, ProbeOne's
// error was discarded entirely (only aggregate counters ever left this
// function), so a wrong -platform-url, a revoked jwt, and a pin mismatch all
// produced an identical `failed=N` with nothing to distinguish them --
// making a broken prober running unattended on a VPS undebuggable without
// adding print statements and redeploying. To avoid flooding the log when
// every provider fails the same way, only the first maxLoggedDistinctErrors
// DISTINCT error messages are logged in detail (each with the provider id
// that first produced it); beyond that, one notice is logged noting further
// detail is suppressed. The total failure count is unaffected and always
// visible via the returned Summary.
func (s *Scheduler) Run(ctx context.Context, providerClientIds []string) Summary {
	s.prune()
	// Re-arm the prober's per-pass error-log gates (and report what the last
	// pass withheld). Their cap is only safe because every pass starts clean:
	// a permanent cap would let ten transient errors silence a later fault
	// that breaks every provider.
	if s.Prober != nil {
		s.Prober.ResetErrorLogging()
	}

	concurrency := s.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	var mu sync.Mutex
	var sum Summary
	loggedErrors := map[string]bool{}
	suppressedNoted := false

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// recentlyProbed only becomes true once a probe COMPLETES, so a duplicate
	// id inside one batch would otherwise open two tunnels to the same
	// provider simultaneously and pay the contract cost twice. The enumeration
	// path de-duplicates before it gets here; the due path is whatever the
	// server sent.
	seen := map[string]bool{}

	for i, id := range providerClientIds {
		if seen[id] {
			mu.Lock()
			sum.Skipped++
			mu.Unlock()
			continue
		}
		seen[id] = true

		// A dead context stops the pass here, before any further tunnel is
		// built. providertunnel.Open constructs a full netstack before it
		// ever consults the context, so without this check every remaining
		// provider in the batch would get a real tunnel built and torn down
		// just so its probe could fail instantly -- a 500-provider batch
		// reporting hundreds of spurious failures (and, in single-shot mode,
		// exiting non-zero blaming the providers) when the truth is that the
		// operator sent SIGTERM. The explicit Err check runs first because
		// select chooses randomly among ready cases: with the semaphore free
		// AND the context dead, the select below may still pick the
		// semaphore.
		cancelled := ctx.Err() != nil
		if !cancelled {
			if s.recentlyProbed(id) {
				mu.Lock()
				sum.Skipped++
				mu.Unlock()
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				cancelled = true
			}
		}
		if cancelled {
			remaining := len(providerClientIds) - i
			mu.Lock()
			sum.Skipped += remaining
			mu.Unlock()
			log.Printf("prober: run cancelled (%v); skipping the %d remaining provider(s) in this pass", ctx.Err(), remaining)
			break
		}

		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			mu.Lock()
			sum.Attempted++
			mu.Unlock()

			err := s.Prober.ProbeOne(ctx, id)

			mu.Lock()
			if err != nil {
				sum.Failed++
				msg := err.Error()
				if !loggedErrors[msg] {
					if len(loggedErrors) < maxLoggedDistinctErrors {
						loggedErrors[msg] = true
						log.Printf("prober: probe failed provider=%s: %s", id, err)
					} else if !suppressedNoted {
						suppressedNoted = true
						log.Printf("prober: %d+ distinct probe errors this pass; suppressing further per-error detail (see the pass's failed count for the total)", maxLoggedDistinctErrors)
					}
				}
			} else {
				sum.Submitted++
			}
			mu.Unlock()

			if err == nil {
				s.markProbed(id)
			}
		}(id)
	}
	wg.Wait()
	return sum
}
