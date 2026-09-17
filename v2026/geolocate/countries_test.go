package geolocate

import (
	"strings"
	"testing"
)

func TestIsoCountryNamesCoverage(t *testing.T) {
	// All 249 codes currently assigned in ISO 3166-1.
	if len(isoCountryNames) != 249 {
		t.Fatalf("len(isoCountryNames) = %d, want 249", len(isoCountryNames))
	}
	for code, name := range isoCountryNames {
		if len(code) != 2 {
			t.Fatalf("key %q is not alpha-2", code)
		}
		if code != strings.ToUpper(code) {
			t.Fatalf("key %q is not uppercase", code)
		}
		if name == "" {
			t.Fatalf("code %q has an empty name", code)
		}
	}
}

func TestCountryNameForCode(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{"US", "United States"},
		{"us", "United States"},
		{" De ", "Germany"},
		{"GB", "United Kingdom"},
		{"KR", "South Korea"}, // ISO short name is the comma-inverted "Korea, Republic of"
		{"ZZ", ""},            // not a real ISO-3166-1 code
		{"", ""},
	}
	for _, c := range cases {
		if got := countryNameForCode(c.code); got != c.want {
			t.Errorf("countryNameForCode(%q) = %q, want %q", c.code, got, c.want)
		}
	}
}
