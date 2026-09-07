package geolocate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

// SourceDiagnosticClass is a fixed, non-sensitive result class for one
// geolocation source. It deliberately cannot carry an error message, status
// code, URL, certificate, response, or provider identity.
type SourceDiagnosticClass string

const (
	SourceDiagnosticSuccess      SourceDiagnosticClass = "success"
	SourceDiagnosticDNS          SourceDiagnosticClass = "dns"
	SourceDiagnosticTimeout      SourceDiagnosticClass = "timeout"
	SourceDiagnosticConnect      SourceDiagnosticClass = "connect"
	SourceDiagnosticTLSOrPin     SourceDiagnosticClass = "tls_or_pin"
	SourceDiagnosticHTTPStatus   SourceDiagnosticClass = "http_status"
	SourceDiagnosticResponseRead SourceDiagnosticClass = "response_read"
	SourceDiagnosticResponseSize SourceDiagnosticClass = "response_size"
	SourceDiagnosticParse        SourceDiagnosticClass = "parse"
	SourceDiagnosticRequest      SourceDiagnosticClass = "request"
)

// SourceDiagnosticStage is the bounded request stage at which a source
// finished or failed.
type SourceDiagnosticStage string

const (
	SourceDiagnosticStageRequest         SourceDiagnosticStage = "request"
	SourceDiagnosticStageDNS             SourceDiagnosticStage = "dns"
	SourceDiagnosticStageConnect         SourceDiagnosticStage = "connect_formation"
	SourceDiagnosticStageTLS             SourceDiagnosticStage = "tls"
	SourceDiagnosticStageResponseHeaders SourceDiagnosticStage = "response_headers"
	SourceDiagnosticStageResponseBody    SourceDiagnosticStage = "response_body"
	SourceDiagnosticStageParse           SourceDiagnosticStage = "parse"
	SourceDiagnosticStageComplete        SourceDiagnosticStage = "complete"
)

// SourceDiagnosticElapsed is a bounded elapsed-time bucket. Exact request
// timing is unnecessary for the cold-tunnel discriminator and would create a
// high-cardinality log field.
type SourceDiagnosticElapsed string

const (
	SourceDiagnosticElapsedUnder1s SourceDiagnosticElapsed = "lt1s"
	SourceDiagnosticElapsed1To5s   SourceDiagnosticElapsed = "1s_to_5s"
	SourceDiagnosticElapsed5To15s  SourceDiagnosticElapsed = "5s_to_15s"
	SourceDiagnosticElapsed15To30s SourceDiagnosticElapsed = "15s_to_30s"
	SourceDiagnosticElapsed30sPlus SourceDiagnosticElapsed = "gte30s"
)

// SourceDiagnostic is the complete privacy-safe observation for one source.
// Source is a compile-time alias from sources.go, or "other" for any test or
// future source not yet added to the allowlist.
type SourceDiagnostic struct {
	Source  string
	Class   SourceDiagnosticClass
	Stage   SourceDiagnosticStage
	Elapsed SourceDiagnosticElapsed
}

// SourceErrorClassifier lets the transport owner classify a typed error that
// a generic HTTP client cannot see precisely. The production fixed-provider
// tunnel uses it only for its existing certificate-pin sentinels. Returned
// values are normalized back to the fixed enums before they leave this
// package.
type SourceErrorClassifier func(error) (SourceDiagnosticClass, SourceDiagnosticStage, bool)

type noConsensusError struct {
	diagnostics []SourceDiagnostic
}

func (self *noConsensusError) Error() string { return ErrNoConsensus.Error() }
func (self *noConsensusError) Unwrap() error { return ErrNoConsensus }

// sourceDiagnostics is deliberately unexported. An error from another package
// cannot impersonate a diagnostic-bearing geolocation result and inject an
// arbitrary string into the scheduler's aggregate.
func (self *noConsensusError) sourceDiagnostics() []SourceDiagnostic {
	return append([]SourceDiagnostic(nil), self.diagnostics...)
}

// SourceDiagnostics returns the bounded per-source observations carried by a
// no-consensus error. A bare ErrNoConsensus from an alternate/test Locator has
// none. The returned slice is a copy.
func SourceDiagnostics(err error) []SourceDiagnostic {
	var diagnosticErr interface {
		sourceDiagnostics() []SourceDiagnostic
	}
	if !errors.As(err, &diagnosticErr) {
		return nil
	}
	return diagnosticErr.sourceDiagnostics()
}

func newNoConsensusError(diagnostics []SourceDiagnostic) error {
	return &noConsensusError{diagnostics: append([]SourceDiagnostic(nil), diagnostics...)}
}

func sourceDiagnosticAlias(name string) string {
	switch name {
	case "ip.pn", "freeipapi", "ipinfo":
		return name
	default:
		return "other"
	}
}

func sourceDiagnosticElapsed(elapsed time.Duration) SourceDiagnosticElapsed {
	switch {
	case elapsed < time.Second:
		return SourceDiagnosticElapsedUnder1s
	case elapsed < 5*time.Second:
		return SourceDiagnosticElapsed1To5s
	case elapsed < 15*time.Second:
		return SourceDiagnosticElapsed5To15s
	case elapsed < 30*time.Second:
		return SourceDiagnosticElapsed15To30s
	default:
		return SourceDiagnosticElapsed30sPlus
	}
}

func normalizeSourceDiagnosticClass(class SourceDiagnosticClass) SourceDiagnosticClass {
	switch class {
	case SourceDiagnosticSuccess,
		SourceDiagnosticDNS,
		SourceDiagnosticTimeout,
		SourceDiagnosticConnect,
		SourceDiagnosticTLSOrPin,
		SourceDiagnosticHTTPStatus,
		SourceDiagnosticResponseRead,
		SourceDiagnosticResponseSize,
		SourceDiagnosticParse,
		SourceDiagnosticRequest:
		return class
	default:
		return SourceDiagnosticConnect
	}
}

func normalizeSourceDiagnosticFailureClass(class SourceDiagnosticClass) SourceDiagnosticClass {
	class = normalizeSourceDiagnosticClass(class)
	if class == SourceDiagnosticSuccess {
		return SourceDiagnosticConnect
	}
	return class
}

func normalizeSourceDiagnosticStage(stage SourceDiagnosticStage) SourceDiagnosticStage {
	switch stage {
	case SourceDiagnosticStageRequest,
		SourceDiagnosticStageDNS,
		SourceDiagnosticStageConnect,
		SourceDiagnosticStageTLS,
		SourceDiagnosticStageResponseHeaders,
		SourceDiagnosticStageResponseBody,
		SourceDiagnosticStageParse,
		SourceDiagnosticStageComplete:
		return stage
	default:
		return SourceDiagnosticStageConnect
	}
}

func newSourceDiagnostic(name string, class SourceDiagnosticClass, stage SourceDiagnosticStage, elapsed time.Duration) SourceDiagnostic {
	return SourceDiagnostic{
		Source:  sourceDiagnosticAlias(name),
		Class:   normalizeSourceDiagnosticClass(class),
		Stage:   normalizeSourceDiagnosticStage(stage),
		Elapsed: sourceDiagnosticElapsed(elapsed),
	}
}

type sourceRequestProgress uint32

const (
	sourceRequestStarted sourceRequestProgress = iota
	sourceRequestDNS
	sourceRequestConnect
	sourceRequestTLS
	sourceRequestResponseHeaders
)

type sourceProgress struct {
	stage atomic.Uint32
}

func (self *sourceProgress) advance(stage sourceRequestProgress) {
	for current := self.stage.Load(); current < uint32(stage); current = self.stage.Load() {
		if self.stage.CompareAndSwap(current, uint32(stage)) {
			return
		}
	}
}

func (self *sourceProgress) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { self.advance(sourceRequestDNS) },
		ConnectStart:      func(string, string) { self.advance(sourceRequestConnect) },
		TLSHandshakeStart: func() { self.advance(sourceRequestTLS) },
		GotConn:           func(httptrace.GotConnInfo) { self.advance(sourceRequestResponseHeaders) },
		GotFirstResponseByte: func() {
			self.advance(sourceRequestResponseHeaders)
		},
	}
}

func (self *sourceProgress) diagnosticStage() SourceDiagnosticStage {
	switch sourceRequestProgress(self.stage.Load()) {
	case sourceRequestDNS:
		return SourceDiagnosticStageDNS
	case sourceRequestConnect:
		return SourceDiagnosticStageConnect
	case sourceRequestTLS:
		return SourceDiagnosticStageTLS
	case sourceRequestResponseHeaders:
		return SourceDiagnosticStageResponseHeaders
	default:
		// The fixed-provider transport owns dialing inside DialTLSContext, so
		// it may emit no net/http trace event before a cold formation timeout.
		return SourceDiagnosticStageConnect
	}
}

func sourceErrorIsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func classifySourceRequestError(err error, progress *sourceProgress, classify SourceErrorClassifier) (SourceDiagnosticClass, SourceDiagnosticStage) {
	if classify != nil {
		if class, stage, ok := classify(err); ok {
			return normalizeSourceDiagnosticFailureClass(class), normalizeSourceDiagnosticStage(stage)
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return SourceDiagnosticDNS, SourceDiagnosticStageDNS
	}

	var certificateVerificationErr *tls.CertificateVerificationError
	var unknownAuthorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certificateInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certificateVerificationErr) ||
		errors.As(err, &unknownAuthorityErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &certificateInvalidErr) {
		return SourceDiagnosticTLSOrPin, SourceDiagnosticStageTLS
	}

	if sourceErrorIsTimeout(err) {
		return SourceDiagnosticTimeout, progress.diagnosticStage()
	}
	if progress.diagnosticStage() == SourceDiagnosticStageTLS {
		return SourceDiagnosticTLSOrPin, SourceDiagnosticStageTLS
	}

	return SourceDiagnosticConnect, progress.diagnosticStage()
}
