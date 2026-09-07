package geolocate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type source struct {
	Name  string
	URL   string
	Parse func([]byte) (SourceResult, error)
}

// sources are the production geolocation endpoints. Each uses the no-IP
// "my location" form, so a request routed through a provider returns that
// provider's egress location.
var sources = []source{
	{Name: "ip.pn", URL: "https://api.i.pn/json", Parse: parseIpPn},
	{Name: "freeipapi", URL: "https://free.freeipapi.com/api/json", Parse: parseFreeIpApi},
	{Name: "ipinfo", URL: "https://ipinfo.io/json", Parse: parseIpInfo},
}

// SourceHosts returns the host of every production source, de-duplicated and
// in table order.
//
// This exists so nothing outside the package has to keep a second copy of the
// endpoint list. The confinement self-check (see confinement/) must attempt a
// direct connection to exactly the hosts geolocate will later reach through a
// tunnel; a hand-maintained copy of that list would drift from this table on
// the first endpoint change, and the check would keep passing while no longer
// covering a real endpoint.
//
// A URL that does not parse, or that carries no host, is skipped rather than
// panicking -- but sources is a compile-time constant table, and
// TestSourceHostsCoversEverySource fails if any entry goes missing here.
func SourceHosts() []string {
	seen := map[string]bool{}
	hosts := make([]string, 0, len(sources))
	for _, s := range sources {
		u, err := url.Parse(s.URL)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

func parseIpPn(b []byte) (SourceResult, error) {
	var v struct {
		Status      string          `json:"status"`
		Country     string          `json:"country"`
		CountryCode string          `json:"countryCode"`
		City        string          `json:"city"`
		RegionName  string          `json:"regionName"`
		ASN         json.RawMessage `json:"asn"`
		Mobile      bool            `json:"mobile"`
		Proxy       bool            `json:"proxy"`
		Hosting     bool            `json:"hosting"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return SourceResult{}, err
	}
	if v.Status != "" && v.Status != "success" {
		return SourceResult{}, fmt.Errorf("ip.pn status %q", v.Status)
	}
	return SourceResult{
		CountryCode: v.CountryCode,
		Country:     v.Country,
		City:        v.City,
		Region:      v.RegionName,
		ASN:         parseASNValue(v.ASN),
		Mobile:      v.Mobile,
		Proxy:       v.Proxy,
		Hosting:     v.Hosting,
		// ip.pn is the only source that carries all three.
		Supports: FlagSupport{Hosting: true, Proxy: true, Mobile: true},
	}, nil
}

func parseFreeIpApi(b []byte) (SourceResult, error) {
	var v struct {
		CountryName string          `json:"countryName"`
		CountryCode string          `json:"countryCode"`
		CityName    string          `json:"cityName"`
		RegionName  string          `json:"regionName"`
		ASN         json.RawMessage `json:"asn"`
		IsProxy     bool            `json:"isProxy"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return SourceResult{}, err
	}
	return SourceResult{
		CountryCode: v.CountryCode,
		Country:     v.CountryName,
		City:        v.CityName,
		Region:      v.RegionName,
		ASN:         parseASNValue(v.ASN),
		Proxy:       v.IsProxy,
		// freeipapi exposes isProxy and nothing equivalent for the other two.
		Supports: FlagSupport{Proxy: true},
	}, nil
}

// parseASNValue tolerantly extracts an ASN integer from a raw JSON value that
// these free APIs are known to represent inconsistently: a bare JSON number
// (401486), a quoted number ("401486"), or a quoted "AS"-prefixed form
// ("AS401486"). Any other shape (null, absent, object, array, garbage)
// degrades to 0 rather than failing the whole payload's parse.
func parseASNValue(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimPrefix(strings.TrimSpace(s), "AS")
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return 0
}

func parseIpInfo(b []byte) (SourceResult, error) {
	var v struct {
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"` // alpha-2, e.g. "US"
		Org     string `json:"org"`     // e.g. "AS401486 RAVNIX LLC"
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return SourceResult{}, err
	}
	asn, org := parseASNOrg(v.Org)
	// ipinfo gives only the alpha-2 country code, no human-readable name.
	return SourceResult{
		CountryCode: v.Country,
		City:        v.City,
		Region:      v.Region,
		ASN:         asn,
		Org:         org,
	}, nil
}

// parseASNOrg splits ipinfo's org field "AS401486 RAVNIX LLC" into
// (401486, "RAVNIX LLC"). On any unexpected shape it returns (0, org).
func parseASNOrg(org string) (int, string) {
	org = strings.TrimSpace(org)
	if org == "" {
		return 0, ""
	}
	fields := strings.SplitN(org, " ", 2)
	name := ""
	if len(fields) == 2 {
		name = fields[1]
	}
	if strings.HasPrefix(fields[0], "AS") {
		if n, err := strconv.Atoi(fields[0][2:]); err == nil {
			return n, name
		}
	}
	return 0, org
}
