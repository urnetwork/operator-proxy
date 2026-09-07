package geolocate

import "testing"

func TestConsensusCountryMajorityCityDisagree(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", Country: "United States", City: "Fairfax", ASN: 401486},
		{Name: "b", OK: true, CountryCode: "US", Country: "United States", City: "Denver", Region: "Colorado", ASN: 401486},
		{Name: "c", OK: true, CountryCode: "US", City: "Atlanta", Region: "Georgia", ASN: 401486},
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("expected CountryConfident with 3 agreeing sources")
	}
	if loc.CountryCode != "us" {
		t.Fatalf("CountryCode = %q, want \"us\"", loc.CountryCode)
	}
	if loc.Country != "United States" {
		t.Fatalf("Country = %q, want \"United States\"", loc.Country)
	}
	if loc.CityConfident {
		t.Fatal("cities disagree (Fairfax/Denver/Atlanta); CityConfident must be false")
	}
	if loc.City != "" {
		t.Fatalf("City = %q, want empty on disagreement", loc.City)
	}
	if loc.ASN != 401486 {
		t.Fatalf("ASN = %d, want 401486", loc.ASN)
	}
}

func TestConsensusCityAgreementNormalized(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", City: "Denver", Region: "Colorado"},
		{Name: "b", OK: true, CountryCode: "US", City: "denver ", Region: "CO"},
		{Name: "c", OK: true, CountryCode: "US", City: "Atlanta"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("two sources agree on Denver (normalized); CityConfident must be true")
	}
	if got := loc.City; got != "Denver" && got != "denver" {
		t.Fatalf("City = %q, want a Denver display value", got)
	}
	if loc.Region == "" {
		t.Fatal("Region should be carried from an agreeing source")
	}
}

func TestConsensusCountryDisagreementNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US"},
		{Name: "b", OK: true, CountryCode: "CA"},
	}
	loc := consensus(ok)
	if loc.CountryConfident {
		t.Fatal("split country (US vs CA) must not be confident")
	}
	if loc.CountryCode != "" {
		t.Fatalf("CountryCode = %q, want empty on split", loc.CountryCode)
	}
}

// TestConsensusCountryTieBrokenBySourcePriority exercises a genuine 2-vs-2
// tie (both sides clear MinSources) where the lexicographically larger code
// ("us") comes from the higher-priority sources (ip.pn, ipinfo) and the
// lexicographically smaller code ("ca") comes from a lower-priority source
// (freeipapi) plus a repeated ipinfo vote. Under the old buggy tie-break
// (n == bestN && c < best), "ca" would win purely because it sorts before
// "us". The fix requires the higher-priority source's answer to win instead.
func TestConsensusCountryTieBrokenBySourcePriority(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States"},
		{Name: "ipinfo", OK: true, CountryCode: "US", Country: "United States"},
		{Name: "freeipapi", OK: true, CountryCode: "CA", Country: "Canada"},
		{Name: "ipinfo", OK: true, CountryCode: "CA", Country: "Canada"},
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("2-vs-2 tie with both sides >= MinSources must still be confident")
	}
	if loc.CountryCode != "us" {
		t.Fatalf("CountryCode = %q, want \"us\" (ip.pn is highest-priority source and voted US)", loc.CountryCode)
	}
	if loc.Country != "United States" {
		t.Fatalf("Country = %q, want \"United States\"", loc.Country)
	}
}

// TestConsensusCityTieBrokenBySourcePriority is the city analogue of
// TestConsensusCountryTieBrokenBySourcePriority: a 2-vs-2 tie where the
// lexicographically larger city ("denver") is backed by the highest-priority
// source (ip.pn) while the lexicographically smaller city ("chicago") is
// backed only by lower-priority sources. The old lexicographic tie-break
// would pick "chicago"; the fix must pick "denver".
func TestConsensusCityTieBrokenBySourcePriority(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", City: "Denver", Region: "Colorado"},
		{Name: "ipinfo", OK: true, CountryCode: "US", City: "Denver", Region: "Colorado"},
		{Name: "freeipapi", OK: true, CountryCode: "US", City: "Chicago", Region: "Illinois"},
		{Name: "ipinfo", OK: true, CountryCode: "US", City: "Chicago", Region: "Illinois"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("2-vs-2 city tie with both sides >= 2 must still be confident")
	}
	if loc.City != "Denver" {
		t.Fatalf("City = %q, want \"Denver\" (ip.pn is highest-priority source and voted Denver)", loc.City)
	}
}

// TestConsensusCountryNameFallbackFromTable is the teeth-check for the
// ipinfo-name gap: ipinfo returns a country code but never a name (see
// parseIpInfo in sources.go). A quorum consisting only of sources that
// likewise contributed no name (simulated here as "ipinfo" plus another
// nameless source) must not surface CountryConfident==true with an empty
// Country -- the server rejects that with "Missing country." Country must
// be backfilled from the ISO-3166-1 table.
func TestConsensusCountryNameFallbackFromTable(t *testing.T) {
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "DE"},
		{Name: "freeipapi", OK: true, CountryCode: "DE"}, // no Country set, simulating a nameless response
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("expected CountryConfident with 2 agreeing sources")
	}
	if loc.CountryCode != "de" {
		t.Fatalf("CountryCode = %q, want \"de\"", loc.CountryCode)
	}
	if loc.Country != "Germany" {
		t.Fatalf("Country = %q, want \"Germany\" (backfilled from the ISO table)", loc.Country)
	}
}

// TestConsensusCountryNameSourceWinsOverTable verifies the table is only a
// fallback: when a source does supply a name, that name wins even if it
// differs from the table's value (e.g. a source using the official long
// form where the table uses the common short form).
func TestConsensusCountryNameSourceWinsOverTable(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States of America"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States of America"},
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("expected CountryConfident with 2 agreeing sources")
	}
	if loc.Country != "United States of America" {
		t.Fatalf("Country = %q, want the source-supplied name to win over the table's \"United States\"", loc.Country)
	}
}

// TestConsensusUnknownCountryCodeDegradesToNotConfident is the country
// analogue of TestConsensusCityAgreementNoRegionNotConfident, and replaces an
// earlier test that asserted the broken behavior (CountryConfident==true with
// an empty Country).
//
// A code outside the ISO-3166-1 table -- XK (Kosovo, user-assigned) and the
// MaxMind-lineage A1/A2/AP are all real codes free geolocation APIs emit --
// resolves to no name, and no name may be fabricated from the code. But
// "confident" must then mean confident about a record the server will accept:
// the server rejects an empty country with "Missing country.", the rejection
// is not cached by the scheduler, and the provider is therefore re-probed and
// re-rejected on every pass forever. CountryConfident must mean "I have a
// complete, usable country record", so an unnameable code degrades to
// not-confident instead of producing a doomed submission.
func TestConsensusUnknownCountryCodeDegradesToNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "XK"},
		{Name: "freeipapi", OK: true, CountryCode: "XK"},
	}
	loc := consensus(ok)
	if loc.CountryConfident {
		t.Fatal("a country code with no resolvable name must not be country-confident: the server rejects it with \"Missing country.\" and the failure is never cached, so the provider retries forever")
	}
	if loc.Country != "" {
		t.Fatalf("Country = %q, want empty: a name must never be fabricated from the code", loc.Country)
	}
	if loc.CountryCode != "" {
		t.Fatalf("CountryCode = %q, want empty when the result is not country-confident", loc.CountryCode)
	}
}

// TestConsensusNonAlpha2CountryCodeDegradesToNotConfident covers the second
// server rejection reachable from consensus: normalizeCountry lowercases and
// trims but never validates length, so two sources reporting "USA" used to
// yield CountryCode "usa" with CountryConfident true -- a guaranteed 400
// ("Country code must be alpha-2."), on every pass, forever.
func TestConsensusNonAlpha2CountryCodeDegradesToNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "USA", Country: "United States"},
		{Name: "freeipapi", OK: true, CountryCode: "USA", Country: "United States"},
	}
	loc := consensus(ok)
	if loc.CountryConfident {
		t.Fatal("a non-alpha-2 country code must not be country-confident: the server rejects it with \"Country code must be alpha-2.\"")
	}
	if loc.CountryCode != "" {
		t.Fatalf("CountryCode = %q, want empty when the result is not country-confident", loc.CountryCode)
	}
}

// TestConsensusCityAgreementNoRegionNotConfident is the regression test for
// the availability bug: two sources agree on a city but neither supplied a
// Region. The server rejects any submission with CityConfident==true and an
// empty region, which previously threw away a perfectly good country result
// too (the whole submission is one POST). CityConfident must therefore
// require a non-empty Region, not just city agreement; when the region is
// missing, City/Region must stay empty and CityConfident false so the result
// degrades cleanly to country granularity instead of being rejected outright.
func TestConsensusCityAgreementNoRegionNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", Country: "United States", City: "Denver"},
		{Name: "b", OK: true, CountryCode: "US", Country: "United States", City: "denver "},
	}
	loc := consensus(ok)
	if loc.CityConfident {
		t.Fatal("two sources agree on Denver but neither supplied a Region; CityConfident must be false")
	}
	if loc.City != "" {
		t.Fatalf("City = %q, want empty when no source supplied a Region", loc.City)
	}
	if loc.Region != "" {
		t.Fatalf("Region = %q, want empty when no source supplied a Region", loc.Region)
	}
	// The country result must be unaffected by the incomplete city data.
	if !loc.CountryConfident {
		t.Fatal("country agreement is independent of city completeness; CountryConfident must still be true")
	}
	if loc.CountryCode != "us" {
		t.Fatalf("CountryCode = %q, want \"us\"", loc.CountryCode)
	}
	if loc.Country != "United States" {
		t.Fatalf("Country = %q, want \"United States\"", loc.Country)
	}
}

// TestConsensusCityAgreementWithRegionConfident is the happy-path complement
// to TestConsensusCityAgreementNoRegionNotConfident: two sources agree on a
// city and at least one of them supplied a Region, so CityConfident must
// still be true and both City and Region populated.
func TestConsensusCityAgreementWithRegionConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", City: "Denver"},
		{Name: "b", OK: true, CountryCode: "US", City: "denver ", Region: "Colorado"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("two sources agree on Denver and one supplied a Region; CityConfident must be true")
	}
	if got := loc.City; got != "Denver" && got != "denver" {
		t.Fatalf("City = %q, want a Denver display value", got)
	}
	if loc.Region != "Colorado" {
		t.Fatalf("Region = %q, want \"Colorado\"", loc.Region)
	}
}

// TestConsensusFlagsRequireCorroboration: the net-type flags are held to the
// same standard as the country they travel with. They used to be OR-ed
// across sources, so ONE of three free apis -- compromised, or merely having
// a bad day -- could set Proxy or Hosting on every provider the fleet probes,
// with nothing downstream able to tell a corroborated flag from a solo one.
// Two sources agreeing is the same MinSources bar the country clears.
func TestConsensusFlagsRequireCorroboration(t *testing.T) {
	all := FlagSupport{Hosting: true, Proxy: true, Mobile: true}
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", Supports: all},
		{Name: "b", OK: true, CountryCode: "US", Hosting: true, Proxy: true, Supports: all},
		{Name: "c", OK: true, CountryCode: "US", Hosting: true, Supports: all},
	}
	loc := consensus(ok)
	if !loc.Hosting {
		t.Fatal("Hosting must be set: two sources reported it")
	}
	if loc.Proxy {
		t.Fatal("Proxy must not be set from a single source's say-so")
	}
	if loc.Mobile {
		t.Fatal("Mobile must remain false")
	}
}

// TestConsensusSingleRogueSourceCannotDictateTheRecord is the whole
// single-bad-source threat model in one table. With three sources and one of
// them lying about everything, nothing it alone asserts may reach the record:
// not the country (outvoted), not the flags, not the ASN it invents.
func TestConsensusSingleRogueSourceCannotDictateTheRecord(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States", ASN: 7922,
			Supports: FlagSupport{Hosting: true, Proxy: true, Mobile: true}},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States", ASN: 7922,
			Supports: FlagSupport{Hosting: true, Proxy: true, Mobile: true}},
		{Name: "ipinfo", OK: true, CountryCode: "RU", Country: "Russia", ASN: 64512, Org: "Rogue",
			Hosting: true, Proxy: true, Mobile: true,
			Supports: FlagSupport{Hosting: true, Proxy: true, Mobile: true}},
	}
	loc := consensus(ok)
	if loc.CountryCode != "us" || !loc.CountryConfident {
		t.Fatalf("CountryCode = %q confident=%v, want us/true: two honest sources must outvote one rogue", loc.CountryCode, loc.CountryConfident)
	}
	if loc.Hosting || loc.Proxy || loc.Mobile {
		t.Fatalf("flags hosting=%v proxy=%v mobile=%v, want all false: one source is not corroboration", loc.Hosting, loc.Proxy, loc.Mobile)
	}
	if loc.ASN != 7922 {
		t.Fatalf("ASN = %d, want 7922 (the corroborated one)", loc.ASN)
	}
	if loc.Org == "Rogue" {
		t.Fatal("Org came from the rogue source's uncorroborated ASN")
	}
}

// TestConsensusUncorroboratedASNIsNotAdopted: with every source naming a
// different ASN there is no corroboration to be had, and a plurality of one
// is just the first source winning a coin toss. Leave it empty rather than
// publish a coin toss as a fact.
func TestConsensusUncorroboratedASNIsNotAdopted(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States", ASN: 7922, Org: "Comcast"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States", ASN: 15169, Org: "Google"},
	}
	loc := consensus(ok)
	if loc.ASN != 0 || loc.Org != "" {
		t.Fatalf("ASN = %d Org = %q, want unset: no two sources agreed", loc.ASN, loc.Org)
	}
}

// TestConsensusDisplayFieldsPreferHigherPrioritySource is the regression test
// for the inconsistent display-field rules: country name and region were
// last-writer-wins while the city's display casing was first-writer-wins, so
// which rendering survived depended only on a source's index in the results
// slice. Here every lower-priority source is deliberately placed FIRST and
// offers a worse rendering of the same agreed value: the abbreviation "CO"
// for the region, a shouted city name, and a long-form country name. Under
// either of the old rules at least one of the three assertions below fails.
//
// It matters beyond cosmetics because the server canonicalizes location_name
// permanently, so "CO" would be stored durably in place of "Colorado".
func TestConsensusDisplayFieldsPreferHigherPrioritySource(t *testing.T) {
	// ip.pn (rank 0) is bracketed by lower-priority sources so that BOTH old
	// rules pick wrong: ipinfo is first (beating first-writer-wins on the
	// city display) and freeipapi is last (beating last-writer-wins on the
	// country name and the region).
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "US", City: "DENVER", Region: "CO"},
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States", City: "Denver", Region: "Colorado"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States of America", City: "denver", Region: "Colo."},
	}
	loc := consensus(ok)

	if !loc.CountryConfident {
		t.Fatal("three sources agree on US; CountryConfident must be true")
	}
	if loc.Country != "United States" {
		t.Errorf("Country = %q, want \"United States\" from ip.pn (rank 0), not a later, less-trusted source's rendering", loc.Country)
	}
	if !loc.CityConfident {
		t.Fatal("three sources agree on Denver; CityConfident must be true")
	}
	if loc.City != "Denver" {
		t.Errorf("City = %q, want \"Denver\" from ip.pn (rank 0), not a lower-priority source's casing", loc.City)
	}
	if loc.Region != "Colorado" {
		t.Errorf("Region = %q, want \"Colorado\" from ip.pn (rank 0); the server canonicalizes this name permanently, so an abbreviation from a less-trusted source must not win on slice order", loc.Region)
	}
}

// TestConsensusDisplayFieldsIgnoreEmptyFromTrustedSource is the complement:
// priority decides between renderings that exist, but a more-trusted source
// that omitted the field entirely must not blank out a rendering a
// less-trusted source did supply. ip.pn (rank 0) here names neither the
// country nor the region.
func TestConsensusDisplayFieldsIgnoreEmptyFromTrustedSource(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", City: "Denver"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States of America", City: "Denver", Region: "Colorado"},
	}
	loc := consensus(ok)

	if loc.Country != "United States of America" {
		t.Errorf("Country = %q, want freeipapi's name: the higher-priority source supplied none", loc.Country)
	}
	if !loc.CityConfident {
		t.Fatal("two sources agree on Denver and one supplied a Region; CityConfident must be true")
	}
	if loc.Region != "Colorado" {
		t.Errorf("Region = %q, want \"Colorado\": the higher-priority source supplied no region", loc.Region)
	}
}

// TestConsensusCityAgreementAcrossNameVariants is the regression test for the
// real German probe that motivated the place-name matcher: ip.pn returned no
// city at all, freeipapi returned "Frankfurt am Main (Innenstadt I)" (city
// plus city district) and ipinfo returned "Frankfurt am Main". Two sources
// agreed on Frankfurt in substance, but exact normalized string matching saw
// two different cities, so the whole city result -- and the region with it --
// was discarded and the provider fell back to country granularity.
//
// The two variants must now agree, and the canonical name must be the
// SHORTEST variant the agreeing sources support: "Frankfurt am Main", not the
// district-qualified form only one source asserted.
func TestConsensusCityAgreementAcrossNameVariants(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "DE", Country: "Germany"},
		{Name: "freeipapi", OK: true, CountryCode: "DE", Country: "Germany", City: "Frankfurt am Main (Innenstadt I)", Region: "Hesse"},
		{Name: "ipinfo", OK: true, CountryCode: "DE", City: "Frankfurt am Main", Region: "Hesse"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("freeipapi and ipinfo both report Frankfurt am Main (one with a district suffix); CityConfident must be true")
	}
	if loc.City != "Frankfurt am Main" {
		t.Fatalf("City = %q, want \"Frankfurt am Main\" (the shortest variant both sources support)", loc.City)
	}
	if loc.Region != "Hesse" {
		t.Fatalf("Region = %q, want \"Hesse\"", loc.Region)
	}
	if !loc.CountryConfident || loc.CountryCode != "de" {
		t.Fatalf("CountryConfident = %v, CountryCode = %q, want true / \"de\"", loc.CountryConfident, loc.CountryCode)
	}
}

// TestConsensusCityCanonicalNameIsShortestVariant pins the canonical-name
// rule against the source-priority rule that decides everything else: the
// SHORTEST agreeing variant wins even when it comes from the LEAST trusted
// source. The shortest variant is exactly the assertion every agreeing source
// supports; ip.pn's "Frankfurt am Main" adds specificity that ipinfo never
// confirmed, and the server stores the submitted name permanently.
func TestConsensusCityCanonicalNameIsShortestVariant(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "DE", Country: "Germany", City: "Frankfurt am Main", Region: "Hesse"},
		{Name: "ipinfo", OK: true, CountryCode: "DE", City: "Frankfurt", Region: "Hesse"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("\"Frankfurt\" and \"Frankfurt am Main\" agree; CityConfident must be true")
	}
	if loc.City != "Frankfurt" {
		t.Fatalf("City = %q, want \"Frankfurt\": the shortest variant wins over the more-trusted source's longer one", loc.City)
	}
}

// TestConsensusCityCanonicalNamePreservesDiacritics pins that the display
// name comes from a source's original string and not from the normalized
// match tokens. Accent folding exists only to make "Logroño" and "logrono"
// agree; the stored name must still be "Logroño". Token count ties fall back
// to SourcePriority, so ip.pn's rendering wins here.
func TestConsensusCityCanonicalNamePreservesDiacritics(t *testing.T) {
	ok := []SourceResult{
		{Name: "freeipapi", OK: true, CountryCode: "ES", Country: "Spain", City: "logrono", Region: "La Rioja"},
		{Name: "ip.pn", OK: true, CountryCode: "ES", Country: "Spain", City: "Logroño", Region: "La Rioja"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("\"logrono\" and \"Logroño\" are the same city after accent folding; CityConfident must be true")
	}
	if loc.City != "Logroño" {
		t.Fatalf("City = %q, want \"Logroño\": the display name is rendered from the original string, never from the folded tokens", loc.City)
	}
}

// TestConsensusRegionVariantsMerge exercises the matcher on the region, the
// reason it is applied there too: CityConfident requires a non-empty region,
// so region renderings that only differ by a parenthetical must resolve to
// the shortest form rather than storing one source's qualifier.
func TestConsensusRegionVariantsMerge(t *testing.T) {
	ok := []SourceResult{
		{Name: "freeipapi", OK: true, CountryCode: "DE", Country: "Germany", City: "Frankfurt am Main", Region: "Hesse (HE)"},
		{Name: "ipinfo", OK: true, CountryCode: "DE", City: "Frankfurt am Main", Region: "Hesse"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("both sources report Frankfurt am Main with a region; CityConfident must be true")
	}
	if loc.Region != "Hesse" {
		t.Fatalf("Region = %q, want \"Hesse\": the parenthetical qualifier is not part of the corroborated name", loc.Region)
	}
}

// TestConsensusEmptyCitiesDoNotAgree is the safety complement of the wider
// matching rule: two sources that both reported no city have NOT agreed on a
// city. If an empty name matched an empty name, two silent sources would
// clear the >= 2 threshold and produce CityConfident with an empty City --
// a submission the server rejects, uncached, forever.
func TestConsensusEmptyCitiesDoNotAgree(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "DE", Country: "Germany", Region: "Hesse"},
		{Name: "ipinfo", OK: true, CountryCode: "DE", Region: "Hesse"},
	}
	loc := consensus(ok)
	if loc.CityConfident {
		t.Fatal("neither source named a city; CityConfident must be false")
	}
	if loc.City != "" {
		t.Fatalf("City = %q, want empty", loc.City)
	}
	if loc.Region != "" {
		t.Fatalf("Region = %q, want empty when there is no agreed city", loc.Region)
	}
	if !loc.CountryConfident {
		t.Fatal("the country result must be unaffected")
	}
}

// TestConsensusRetainsDisambiguator is the storage-side half of the
// parenthetical-retention rule. Two sources both report "Frankfurt (Oder)",
// so the qualifier is corroborated, and the published name must keep it:
// publishing a bare "Frankfurt" would discard the only thing distinguishing
// that city from Frankfurt am Main, and the server canonicalizes and stores
// the submitted name permanently.
func TestConsensusRetainsDisambiguator(t *testing.T) {
	ok := []SourceResult{
		{Name: "freeipapi", OK: true, CountryCode: "DE", Country: "Germany", City: "Frankfurt (Oder)", Region: "Brandenburg"},
		{Name: "ipinfo", OK: true, CountryCode: "DE", City: "Frankfurt (Oder)", Region: "Brandenburg"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("both sources report Frankfurt (Oder) with a region; CityConfident must be true")
	}
	if loc.City != "Frankfurt (Oder)" {
		t.Fatalf("City = %q, want \"Frankfurt (Oder)\": a corroborated disambiguator must survive into the stored name", loc.City)
	}
	if loc.Region != "Brandenburg" {
		t.Fatalf("Region = %q, want \"Brandenburg\"", loc.Region)
	}
}

// TestConsensusDifferentFrankfurtsDoNotMerge is the consensus-level teeth of
// the same rule. Frankfurt (Oder) and Frankfurt am Main are different cities
// ~90km apart in different Bundesländer. Under unconditional parenthetical
// stripping the first reduced to "Frankfurt", which prefix-matched the
// second, and consensus published a confident "Frankfurt" with whichever
// region the more-trusted source happened to report -- a wrong location,
// stored permanently. They must not merge; the result degrades to country
// granularity, which is safe and re-probes cleanly.
func TestConsensusDifferentFrankfurtsDoNotMerge(t *testing.T) {
	ok := []SourceResult{
		{Name: "freeipapi", OK: true, CountryCode: "DE", Country: "Germany", City: "Frankfurt (Oder)", Region: "Brandenburg"},
		{Name: "ipinfo", OK: true, CountryCode: "DE", City: "Frankfurt am Main", Region: "Hesse"},
	}
	loc := consensus(ok)
	if loc.CityConfident {
		t.Fatalf("Frankfurt (Oder) and Frankfurt am Main are different cities; CityConfident must be false (got City %q, Region %q)", loc.City, loc.Region)
	}
	if loc.City != "" || loc.Region != "" {
		t.Fatalf("City = %q, Region = %q, want both empty on disagreement", loc.City, loc.Region)
	}
	if !loc.CountryConfident || loc.CountryCode != "de" {
		t.Fatal("the country result must survive the city disagreement")
	}
}
