// Package providertunnel builds an http.Client whose every request egresses
// through one specific urnetwork provider, so a geolocation lookup made with it
// reports that provider's egress location.
package providertunnel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strings"
)

// ErrPinMismatch is returned by the pin check when a pinned host presents a
// certificate chain in which NO certificate's public key -- leaf or
// intermediate -- is in the allowed set. A provider is the network path for
// these requests, so pinning is what stops it forging a location by MITMing
// a geolocation api.
var ErrPinMismatch = errors.New("providertunnel: certificate pin mismatch")

// ErrPinHostUnknown is returned by PinnedTLSConfig's verifier when it cannot
// determine which host it is checking. This happens if the *tls.Config
// returned by PinnedTLSConfig is Clone()'d and ServerName is set on the
// clone: Clone() copies the VerifyPeerCertificate func value, but the
// closure still reads the ORIGINAL config's ServerName field (the clone's
// mutation never reaches it), so the check would otherwise see an empty
// host and, for a naive implementation, silently skip pinning entirely. We
// fail closed instead: an untrusted provider does not get a free pass just
// because a caller used the template incorrectly.
var ErrPinHostUnknown = errors.New("providertunnel: cannot determine host for certificate pin check")

// SPKIPin is the base64 sha-256 of a certificate's subject public key info.
// Pinning the key rather than the certificate means the pin survives
// certificate renewal (new serial number, new validity window, even a new
// CN) as long as the key itself is unchanged.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// normalizeHost lowercases host and strips a trailing ":port" suffix, if
// present, so a pin map key mistakenly written as "ipinfo.io:443" and a
// dialed address of "ipinfo.io:443" both normalize to "ipinfo.io" and match
// each other. net.SplitHostPort is used rather than a manual strings.Cut on
// ":" because it correctly rejects inputs that merely contain a colon but
// are not actually host:port (e.g. leaves a bare hostname alone), so a
// non-host:port string just falls through unchanged.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// normalizePins normalizes pin map keys once (case and any stray :port
// suffix) so lookups are consistent without repeated normalization per
// verification call. This is the single place map keys are normalized;
// checkPin, PinVerifier, and the tunnel-layer allowlist check all normalize
// the host they look up the same way via normalizeHost, so a pin map key
// and a dialed host always compare on equal footing.
// Colliding keys are MERGED, not overwritten: "ipinfo.io" and
// "IPINFO.IO:443" normalize to the same host, and letting one win would
// silently drop the other's pins in map iteration order -- nondeterministic
// which set survived, and a dropped pin is a probe that fails closed against
// the legitimate host after a rotation. Merging is also the safe direction
// for the allowlist, since both keys were already permitted by the caller.
func normalizePins(pins map[string][]string) map[string][]string {
	normalized := make(map[string][]string, len(pins))
	for host, allowed := range pins {
		key := normalizeHost(host)
		if existing, ok := normalized[key]; ok {
			// Copy on first merge rather than appending into the caller's
			// backing array, which append may otherwise write through.
			merged := make([]string, 0, len(existing)+len(allowed))
			merged = append(merged, existing...)
			merged = append(merged, allowed...)
			normalized[key] = merged
			continue
		}
		normalized[key] = allowed
	}
	return normalized
}

// checkPin is the single implementation of the pin check, shared by
// PinVerifier and PinnedTLSConfig so there is exactly one place the pinning
// logic lives.
//
// A match ANYWHERE in the VERIFIED chain is accepted, not just the leaf:
// checkPin walks verifiedChains -- the certification path(s) crypto/tls
// already validated against the trusted root pool -- and accepts as soon as
// any certificate's SPKI pin is in the host's allowed set. This is
// deliberate, not an oversight: the leaf certificates for these hosts
// rotate routinely (Let's Encrypt roughly every 90 days), and leaf-only
// pinning would turn every rotation into a broken probe until someone
// manually re-captures and redeploys the new leaf pin. Pinning the issuing
// intermediate as well means the pin survives routine leaf rotation without
// any redeploy, while still rejecting a MITM that presents a chain-valid
// certificate from a DIFFERENT issuer -- which is the actual threat model
// here (an untrusted provider forging a location by substituting its own
// certificate).
//
// checkPin matches against verifiedChains, NOT rawCerts, and this is
// security-critical, not a style choice. rawCerts is whatever the peer
// SENT: crypto/tls puts rawCerts[1:] into an intermediates pool for path
// building and otherwise never inspects certificates the verified path
// didn't need. That means an attacker holding a leaf for a pinned host
// issued by ANY CA in the trust store can pad the Certificate message with
// the real, publicly-downloadable pinned intermediate as inert dead
// weight: chain verification succeeds via the attacker's own path (their
// leaf straight to their own trusted root/intermediate), and a rawCerts-based
// check would then find the legitimate intermediate's SPKI sitting
// unused in rawCerts and accept -- a complete bypass. Matching against
// verifiedChains closes this: it only ever contains the certificate(s) on
// path(s) crypto/tls actually validated, so a pinned certificate the
// attacker merely appended without it being part of that path cannot
// satisfy the check. This is also what RFC 7469 (S2.6) requires: pins are
// computed over the validated certification path, not the raw presented
// message.
//
// The tradeoff: pinning an intermediate trusts that intermediate CA, not
// just one specific certificate. Any certificate issued by that
// intermediate -- for this host or, in principle, any other identity it is
// willing to sign for -- will satisfy the pin check for this host. That is
// materially broader than leaf-only pinning, and is accepted here because
// the alternative (leaf-only) degrades this into a manual chore roughly
// monthly across the three pinned hosts.
//
// If no certificate in any verified chain matches, the check fails closed
// with ErrPinMismatch.
//
// An empty verifiedChains fails closed. There is deliberately no fallback to
// scanning rawCerts: those are peer-controlled, and matching a pin against
// them IS the dead-weight-intermediate bypass above -- an attacker pads the
// wire chain with a legitimately pinned certificate that was never on the
// validated path. Such a fallback did exist, reachable only from tests that
// called this verifier directly, and it was inert in production for one
// reason: nothing in this package sets InsecureSkipVerify on the exported,
// MUTABLE *tls.Config values PinnedTLSConfig/PinnedTLSConfigForHost return.
// That is a convention, not a guarantee -- one debugging line elsewhere
// would have re-armed the whole bypass with every test still green. The
// tests now build real verified chains instead (see chainOf in
// pinning_test.go), which costs them one helper and removes the branch.
func checkPin(normalized map[string][]string, host string, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return ErrPinMismatch
	}
	allowed, pinned := normalized[normalizeHost(host)]
	if !pinned {
		return nil
	}

	for _, chain := range verifiedChains {
		for _, cert := range chain {
			got := SPKIPin(cert)
			for _, want := range allowed {
				if got == want {
					return nil
				}
			}
		}
	}
	return ErrPinMismatch
}

// PinVerifier returns a VerifyPeerCertificate callback pinned to host. Both
// the pin set and host are captured by value at construction time (host is
// normalized once, up front) so the returned closure holds no reference to
// any *tls.Config. That makes it clone-proof by construction: nothing about
// tls.Config.Clone() can ever decouple this closure from the host it was
// built for, because it never reads a *tls.Config field in the first place.
//
// Most callers should use PinnedTLSConfigForHost rather than calling this
// directly.
func PinVerifier(pins map[string][]string, host string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	normalized := normalizePins(pins)
	host = normalizeHost(host)
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return checkPin(normalized, host, rawCerts, verifiedChains)
	}
}

// PinnedTLSConfigForHost returns a ready-to-use *tls.Config for a single host:
// ServerName is set to host, MinVersion is TLS 1.2, and VerifyPeerCertificate
// is built by PinVerifier so it is immune to the clone-and-mutate trap
// described on ErrPinHostUnknown. This is what callers needing a
// per-connection or per-host config should use, instead of cloning a shared
// PinnedTLSConfig template and mutating ServerName on the clone.
func PinnedTLSConfigForHost(pins map[string][]string, host string) *tls.Config {
	return &tls.Config{
		ServerName:            host,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: PinVerifier(pins, host),
	}
}

// PinnedTLSConfig returns a tls.Config that keeps normal chain verification
// and additionally requires, for each host in pins, that SOME certificate in
// the presented chain -- leaf or intermediate -- has an SPKI pin in the
// allowed values (see checkPin for why a chain-wide match, not leaf-only, is
// the intended behavior). Hosts absent from pins are not pin-checked.
//
// This config is a TEMPLATE, not a per-connection config. Callers may set
// cfg.ServerName directly on the *tls.Config value returned here and use it
// as-is. Do NOT Clone() this config and set ServerName on the clone: Clone()
// copies the VerifyPeerCertificate func value, but the closure still reads
// THIS config's ServerName field, not the clone's, so the clone's pin check
// would be looking at the wrong (likely empty) host. For per-connection or
// per-host configs, build one with PinnedTLSConfigForHost instead, which
// closes over an immutable host and is safe to use freely, including via
// Clone().
//
// As a safety net for the mistake above, if this config's
// VerifyPeerCertificate callback is ever invoked while ServerName is empty,
// it fails closed with ErrPinHostUnknown rather than silently treating the
// connection as unpinned.
func PinnedTLSConfig(pins map[string][]string) *tls.Config {
	normalized := normalizePins(pins)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if cfg.ServerName == "" {
			return ErrPinHostUnknown
		}
		return checkPin(normalized, cfg.ServerName, rawCerts, verifiedChains)
	}
	return cfg
}
