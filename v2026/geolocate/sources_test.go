package geolocate

import (
	"net/url"
	"testing"
)

func TestParseIpPn(t *testing.T) {
	b := []byte(`{"query":"74.50.11.113","status":"success","country":"United States","countryCode":"US","city":"Fairfax","regionName":"","asn":401486,"mobile":false,"proxy":false,"hosting":false}`)
	r, err := parseIpPn(b)
	if err != nil {
		t.Fatalf("parseIpPn err = %v", err)
	}
	if r.CountryCode != "US" || r.Country != "United States" || r.City != "Fairfax" || r.ASN != 401486 {
		t.Fatalf("parseIpPn = %+v", r)
	}
}

func TestParseIpPnFailStatus(t *testing.T) {
	b := []byte(`{"status":"fail","message":"reserved range"}`)
	if _, err := parseIpPn(b); err == nil {
		t.Fatal("expected error on status != success")
	}
}

func TestParseFreeIpApi(t *testing.T) {
	b := []byte(`{"ipVersion":6,"countryName":"United States","countryCode":"US","cityName":"Denver (North Capitol Hill)","regionName":"Colorado","asn":"401486","isProxy":false}`)
	r, err := parseFreeIpApi(b)
	if err != nil {
		t.Fatalf("parseFreeIpApi err = %v", err)
	}
	if r.CountryCode != "US" || r.Country != "United States" || r.City != "Denver (North Capitol Hill)" || r.Region != "Colorado" || r.ASN != 401486 {
		t.Fatalf("parseFreeIpApi = %+v", r)
	}
}

func TestParseIpInfo(t *testing.T) {
	b := []byte(`{"ip":"74.50.11.113","city":"Atlanta","region":"Georgia","country":"US","org":"AS401486 RAVNIX LLC"}`)
	r, err := parseIpInfo(b)
	if err != nil {
		t.Fatalf("parseIpInfo err = %v", err)
	}
	if r.CountryCode != "US" || r.City != "Atlanta" || r.Region != "Georgia" || r.ASN != 401486 || r.Org != "RAVNIX LLC" {
		t.Fatalf("parseIpInfo = %+v", r)
	}
	if r.Country != "" {
		t.Fatalf("ipinfo provides no country name; Country should be empty, got %q", r.Country)
	}
}

func TestParseASNOrg(t *testing.T) {
	cases := []struct {
		name    string
		org     string
		wantASN int
		wantOrg string
	}{
		{"exact AS+space+name", "AS401486 RAVNIX LLC", 401486, "RAVNIX LLC"},
		{"bare org no AS prefix", "RAVNIX LLC", 0, "RAVNIX LLC"},
		{"org merely starts with letters AS", "ASIA PACIFIC NETWORK INFORMATION CENTRE", 0, "ASIA PACIFIC NETWORK INFORMATION CENTRE"},
		{"AS number with no name", "AS401486", 401486, ""},
		{"empty string", "", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asn, org := parseASNOrg(c.org)
			if asn != c.wantASN || org != c.wantOrg {
				t.Fatalf("parseASNOrg(%q) = (%d, %q), want (%d, %q)", c.org, asn, org, c.wantASN, c.wantOrg)
			}
		})
	}
}

func TestParseIpPnASNTypeTolerance(t *testing.T) {
	cases := []struct {
		name    string
		asnJSON string
		wantASN int
	}{
		{"raw number", `401486`, 401486},
		{"quoted number", `"401486"`, 401486},
		{"quoted AS-prefixed", `"AS401486"`, 401486},
		{"null", `null`, 0},
		{"garbage object", `{"foo":"bar"}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := []byte(`{"status":"success","country":"United States","countryCode":"US","city":"Fairfax","regionName":"","asn":` + c.asnJSON + `,"mobile":false,"proxy":false,"hosting":false}`)
			r, err := parseIpPn(b)
			if err != nil {
				t.Fatalf("parseIpPn err = %v", err)
			}
			if r.CountryCode != "US" || r.Country != "United States" || r.City != "Fairfax" {
				t.Fatalf("parseIpPn = %+v", r)
			}
			if r.ASN != c.wantASN {
				t.Fatalf("parseIpPn ASN = %d, want %d", r.ASN, c.wantASN)
			}
		})
	}
}

func TestParseFreeIpApiASNTypeTolerance(t *testing.T) {
	cases := []struct {
		name    string
		asnJSON string
		wantASN int
	}{
		{"quoted AS-prefixed", `"AS401486"`, 401486},
		{"raw number", `401486`, 401486},
		{"quoted number", `"401486"`, 401486},
		{"null", `null`, 0},
		{"garbage array", `[1,2,3]`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := []byte(`{"ipVersion":6,"countryName":"United States","countryCode":"US","cityName":"Denver (North Capitol Hill)","regionName":"Colorado","asn":` + c.asnJSON + `,"isProxy":false}`)
			r, err := parseFreeIpApi(b)
			if err != nil {
				t.Fatalf("parseFreeIpApi err = %v", err)
			}
			if r.CountryCode != "US" || r.Country != "United States" || r.City != "Denver (North Capitol Hill)" || r.Region != "Colorado" {
				t.Fatalf("parseFreeIpApi = %+v", r)
			}
			if r.ASN != c.wantASN {
				t.Fatalf("parseFreeIpApi ASN = %d, want %d", r.ASN, c.wantASN)
			}
		})
	}
}

func TestSourcesTable(t *testing.T) {
	wantNames := []string{"ip.pn", "freeipapi", "ipinfo"}
	if len(sources) != len(wantNames) {
		t.Fatalf("len(sources) = %d, want %d", len(sources), len(wantNames))
	}
	for i, s := range sources {
		if s.Name != wantNames[i] {
			t.Fatalf("sources[%d].Name = %q, want %q", i, s.Name, wantNames[i])
		}
		if s.URL == "" {
			t.Fatalf("sources[%d] (%s) has empty URL", i, s.Name)
		}
		if s.Parse == nil {
			t.Fatalf("sources[%d] (%s) has nil Parse", i, s.Name)
		}
	}

	// The consensus tie-break in consensus.go is keyed on these exact Name
	// strings via SourcePriority. If the two tables drift apart, tie-breaking
	// silently degrades to the unknown-source fallback rank with no other
	// test failure, so assert the tables stay in lockstep here.
	if len(sources) != len(SourcePriority) {
		t.Fatalf("len(sources) = %d, len(SourcePriority) = %d; tables have drifted apart", len(sources), len(SourcePriority))
	}
	for _, s := range sources {
		if _, ok := SourcePriority[s.Name]; !ok {
			t.Fatalf("source %q has no entry in SourcePriority (consensus.go); tables have drifted apart", s.Name)
		}
	}
}

// TestSourceHostsCoversEverySource is an anti-drift test. SourceHosts is what
// the confinement self-check probes: if a source is added to the table above
// and its host does not come out of SourceHosts, the check silently stops
// covering a real geolocation endpoint while still reporting success.
func TestSourceHostsCoversEverySource(t *testing.T) {
	hosts := SourceHosts()
	if len(hosts) == 0 {
		t.Fatal("SourceHosts is empty; the confinement check would have nothing to test")
	}
	for _, s := range sources {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatalf("source %q has an unparseable URL %q: %s", s.Name, s.URL, err)
		}
		found := false
		for _, h := range hosts {
			if h == u.Hostname() {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("source %q (%s) has no host in SourceHosts %v; the confinement check would not cover it", s.Name, s.URL, hosts)
		}
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" {
			t.Fatalf("SourceHosts contains an empty host: %v", hosts)
		}
		if seen[h] {
			t.Fatalf("SourceHosts contains %q twice: %v", h, hosts)
		}
		seen[h] = true
	}
}

// TestFlagsAreReachableThroughTheRealParsers is the regression test for a
// corroboration bar no source set could clear. Only ip.pn's parser populates
// hosting and mobile (freeipapi carries proxy; ipinfo carries none), so a flat
// two-vote threshold made those two fields permanently false -- a silent total
// loss of the signal rather than a conservative default. This drives the REAL
// parsers, which is the only way to see that: a test hand-building
// SourceResult{Hosting: true} for two sources asserts a shape no parser in
// this repo can emit.
func TestFlagsAreReachableThroughTheRealParsers(t *testing.T) {
	ipPn, err := parseIpPn([]byte(`{"status":"success","countryCode":"US","country":"United States","asn":7922,"hosting":true,"proxy":true,"mobile":true}`))
	if err != nil {
		t.Fatalf("parseIpPn: %s", err)
	}
	ipPn.Name, ipPn.OK = "ip.pn", true

	freeIpApi, err := parseFreeIpApi([]byte(`{"countryCode":"US","countryName":"United States","asn":"7922","isProxy":true}`))
	if err != nil {
		t.Fatalf("parseFreeIpApi: %s", err)
	}
	freeIpApi.Name, freeIpApi.OK = "freeipapi", true

	ipInfo, err := parseIpInfo([]byte(`{"country":"US","org":"AS7922 Comcast"}`))
	if err != nil {
		t.Fatalf("parseIpInfo: %s", err)
	}
	ipInfo.Name, ipInfo.OK = "ipinfo", true

	loc := consensus([]SourceResult{ipPn, freeIpApi, ipInfo})

	// hosting and mobile: ip.pn is the only source capable of them, so its
	// word is the most corroboration obtainable and must be enough.
	if !loc.Hosting {
		t.Error("Hosting is unreachable: only ip.pn's parser can report it, so requiring two votes makes it permanently false")
	}
	if !loc.Mobile {
		t.Error("Mobile is unreachable for the same reason as Hosting")
	}
	// proxy: two sources can report it, so two must agree -- and here they do.
	if !loc.Proxy {
		t.Error("Proxy is unreachable: ip.pn and freeipapi both reported it")
	}

	// ...and with only the freeipapi vote, proxy stays unset, because a
	// second capable source (ip.pn) declined to corroborate it.
	ipPnClean, _ := parseIpPn([]byte(`{"status":"success","countryCode":"US","country":"United States","asn":7922}`))
	ipPnClean.Name, ipPnClean.OK = "ip.pn", true
	if consensus([]SourceResult{ipPnClean, freeIpApi, ipInfo}).Proxy {
		t.Error("Proxy was set on one vote although a second capable source did not corroborate it")
	}
}
