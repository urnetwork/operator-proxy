package geolocate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type diagnosticRoundTripper func(*http.Request) (*http.Response, error)

func (self diagnosticRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

type diagnosticErrorReader struct {
	err error
}

func (self diagnosticErrorReader) Read([]byte) (int, error) { return 0, self.err }
func (self diagnosticErrorReader) Close() error             { return nil }

func diagnosticTestClock(elapsed time.Duration) func() time.Time {
	start := time.Unix(100, 0)
	calls := 0
	return func() time.Time {
		calls++
		if calls == 1 {
			return start
		}
		return start.Add(elapsed)
	}
}

func diagnosticResponse(status int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Body: body, Header: http.Header{}}
}

func TestFetchSourceClassifiesOnlyBoundedDiagnosticFields(t *testing.T) {
	pinErr := errors.New("synthetic pin mismatch with private certificate detail")
	parseSuccess := func([]byte) (SourceResult, error) {
		return SourceResult{CountryCode: "US", Country: "United States"}, nil
	}
	tests := []struct {
		name       string
		sourceName string
		url        string
		transport  diagnosticRoundTripper
		parse      func([]byte) (SourceResult, error)
		classify   SourceErrorClassifier
		wantClass  SourceDiagnosticClass
		wantStage  SourceDiagnosticStage
		wantOK     bool
	}{
		{
			name: "dns", sourceName: "ip.pn", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, &net.DNSError{Name: "private-host.invalid", Err: "private resolver detail"}
			},
			parse: parseSuccess, wantClass: SourceDiagnosticDNS, wantStage: SourceDiagnosticStageDNS,
		},
		{
			name: "connect", sourceName: "freeipapi", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("private address refused")}
			},
			parse: parseSuccess, wantClass: SourceDiagnosticConnect, wantStage: SourceDiagnosticStageConnect,
		},
		{
			name: "formation timeout", sourceName: "ipinfo", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("private formation state: %w", context.DeadlineExceeded)
			},
			parse: parseSuccess, wantClass: SourceDiagnosticTimeout, wantStage: SourceDiagnosticStageConnect,
		},
		{
			name: "generic tls", sourceName: "ip.pn", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, &tls.CertificateVerificationError{Err: errors.New("private certificate chain")}
			},
			parse: parseSuccess, wantClass: SourceDiagnosticTLSOrPin, wantStage: SourceDiagnosticStageTLS,
		},
		{
			name: "typed pin", sourceName: "freeipapi", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, pinErr
			},
			parse: parseSuccess,
			classify: func(err error) (SourceDiagnosticClass, SourceDiagnosticStage, bool) {
				if errors.Is(err, pinErr) {
					return SourceDiagnosticTLSOrPin, SourceDiagnosticStageTLS, true
				}
				return "private-class", "private-stage", false
			},
			wantClass: SourceDiagnosticTLSOrPin, wantStage: SourceDiagnosticStageTLS,
		},
		{
			name: "http status", sourceName: "ipinfo", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return diagnosticResponse(http.StatusServiceUnavailable, io.NopCloser(strings.NewReader("private response body"))), nil
			},
			parse: parseSuccess, wantClass: SourceDiagnosticHTTPStatus, wantStage: SourceDiagnosticStageResponseHeaders,
		},
		{
			name: "response read", sourceName: "ip.pn", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return diagnosticResponse(http.StatusOK, diagnosticErrorReader{err: errors.New("private read failure")}), nil
			},
			parse: parseSuccess, wantClass: SourceDiagnosticResponseRead, wantStage: SourceDiagnosticStageResponseBody,
		},
		{
			name: "response body timeout", sourceName: "ipinfo", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return diagnosticResponse(http.StatusOK, diagnosticErrorReader{err: context.DeadlineExceeded}), nil
			},
			parse: parseSuccess, wantClass: SourceDiagnosticTimeout, wantStage: SourceDiagnosticStageResponseBody,
		},
		{
			name: "response size", sourceName: "freeipapi", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				body := strings.NewReader(strings.Repeat("x", MaxResponseBytes+1))
				return diagnosticResponse(http.StatusOK, io.NopCloser(body)), nil
			},
			parse: parseSuccess, wantClass: SourceDiagnosticResponseSize, wantStage: SourceDiagnosticStageResponseBody,
		},
		{
			name: "parse", sourceName: "ipinfo", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return diagnosticResponse(http.StatusOK, io.NopCloser(strings.NewReader("private malformed body"))), nil
			},
			parse: func([]byte) (SourceResult, error) {
				return SourceResult{}, errors.New("private parser detail")
			},
			wantClass: SourceDiagnosticParse, wantStage: SourceDiagnosticStageParse,
		},
		{
			name: "success", sourceName: "ip.pn", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return diagnosticResponse(http.StatusOK, io.NopCloser(strings.NewReader(`{"country":"US"}`))), nil
			},
			parse: parseSuccess, wantClass: SourceDiagnosticSuccess, wantStage: SourceDiagnosticStageComplete, wantOK: true,
		},
		{
			name: "unknown source alias", sourceName: "customer-private-source", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("private transport detail")
			},
			parse: parseSuccess, wantClass: SourceDiagnosticConnect, wantStage: SourceDiagnosticStageConnect,
		},
		{
			name: "invalid custom classification", sourceName: "ip.pn", url: "https://source.invalid/json",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("private transport detail")
			},
			parse: parseSuccess,
			classify: func(error) (SourceDiagnosticClass, SourceDiagnosticStage, bool) {
				return "private-class", "private-stage", true
			},
			wantClass: SourceDiagnosticConnect, wantStage: SourceDiagnosticStageConnect,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, diagnostic := fetchSource(
				context.Background(),
				&http.Client{Transport: test.transport},
				source{Name: test.sourceName, URL: test.url, Parse: test.parse},
				time.Minute,
				test.classify,
				diagnosticTestClock(7*time.Second),
			)
			if result.OK != test.wantOK {
				t.Errorf("OK = %t, want %t", result.OK, test.wantOK)
			}
			if diagnostic.Class != test.wantClass || diagnostic.Stage != test.wantStage {
				t.Errorf("diagnostic = %+v, want class=%s stage=%s", diagnostic, test.wantClass, test.wantStage)
			}
			wantSource := test.sourceName
			if test.sourceName == "customer-private-source" {
				wantSource = "other"
			}
			if diagnostic.Source != wantSource {
				t.Errorf("source alias = %q, want %q", diagnostic.Source, wantSource)
			}
			if diagnostic.Elapsed != SourceDiagnosticElapsed5To15s {
				t.Errorf("elapsed bucket = %q, want %q", diagnostic.Elapsed, SourceDiagnosticElapsed5To15s)
			}
			serialized := fmt.Sprintf("%+v", diagnostic)
			for _, private := range []string{"private", test.url, "503"} {
				if strings.Contains(serialized, private) {
					t.Errorf("diagnostic leaked %q: %s", private, serialized)
				}
			}
		})
	}
}

func TestSourceDiagnosticElapsedBucketsHaveFixedBoundaries(t *testing.T) {
	tests := []struct {
		elapsed time.Duration
		want    SourceDiagnosticElapsed
	}{
		{elapsed: 0, want: SourceDiagnosticElapsedUnder1s},
		{elapsed: time.Second - time.Nanosecond, want: SourceDiagnosticElapsedUnder1s},
		{elapsed: time.Second, want: SourceDiagnosticElapsed1To5s},
		{elapsed: 5 * time.Second, want: SourceDiagnosticElapsed5To15s},
		{elapsed: 15 * time.Second, want: SourceDiagnosticElapsed15To30s},
		{elapsed: 30 * time.Second, want: SourceDiagnosticElapsed30sPlus},
	}
	for _, test := range tests {
		if got := sourceDiagnosticElapsed(test.elapsed); got != test.want {
			t.Errorf("elapsed %s: bucket=%q, want %q", test.elapsed, got, test.want)
		}
	}
}

func TestSourceTimeoutClassificationRetainsLatestRequestStage(t *testing.T) {
	tests := []struct {
		progress sourceRequestProgress
		want     SourceDiagnosticStage
	}{
		{progress: sourceRequestStarted, want: SourceDiagnosticStageConnect},
		{progress: sourceRequestDNS, want: SourceDiagnosticStageDNS},
		{progress: sourceRequestConnect, want: SourceDiagnosticStageConnect},
		{progress: sourceRequestTLS, want: SourceDiagnosticStageTLS},
		{progress: sourceRequestResponseHeaders, want: SourceDiagnosticStageResponseHeaders},
	}
	for _, test := range tests {
		progress := &sourceProgress{}
		progress.advance(test.progress)
		class, stage := classifySourceRequestError(context.DeadlineExceeded, progress, nil)
		if class != SourceDiagnosticTimeout || stage != test.want {
			t.Errorf("progress %d: class/stage=%s/%s, want %s/%s", test.progress, class, stage, SourceDiagnosticTimeout, test.want)
		}
	}
}

func TestNoConsensusErrorPreservesSentinelAndOnlySafeDiagnostics(t *testing.T) {
	privateError := errors.New("raw-secret-error-for-private-host")
	client := &http.Client{Transport: diagnosticRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, privateError
	})}
	srcs := []source{
		{Name: "ip.pn", URL: "https://private-one.invalid", Parse: parseIpPn},
		{Name: "freeipapi", URL: "https://private-two.invalid", Parse: parseFreeIpApi},
		{Name: "customer-private-alias", URL: "https://private-three.invalid", Parse: parseIpInfo},
	}
	_, err := locate(context.Background(), client, srcs, LocateOptions{})
	if !errors.Is(err, ErrNoConsensus) {
		t.Fatalf("err = %v, want it to wrap ErrNoConsensus", err)
	}
	if err.Error() != ErrNoConsensus.Error() {
		t.Fatalf("error text = %q, want only the stable sentinel text", err)
	}
	diagnostics := SourceDiagnostics(err)
	if len(diagnostics) != len(srcs) {
		t.Fatalf("diagnostic count = %d, want %d", len(diagnostics), len(srcs))
	}
	diagnostics[0].Source = "mutation-must-not-reach-error"
	again := SourceDiagnostics(err)
	if again[0].Source == diagnostics[0].Source {
		t.Fatal("SourceDiagnostics returned mutable error-owned storage")
	}
	serialized := fmt.Sprintf("%+v %v", again, err)
	for _, private := range []string{"raw-secret", "private-one", "private-two", "private-three", "customer-private"} {
		if strings.Contains(serialized, private) {
			t.Errorf("no-consensus diagnostic leaked %q: %s", private, serialized)
		}
	}
	if again[2].Source != "other" {
		t.Fatalf("unknown source alias = %q, want other", again[2].Source)
	}
}
