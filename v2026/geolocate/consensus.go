package geolocate

import "strings"

func normalizeCountry(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

// isAlpha2 reports whether code is exactly two ASCII letters, the shape the
// server requires of country_code. It is deliberately ASCII-only: ISO-3166-1
// alpha-2 codes are ASCII by definition, and a non-ASCII two-rune string is a
// source returning something that is not a country code at all.
func isAlpha2(code string) bool {
	if len(code) != 2 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c < 'a' || 'z' < c {
			if c < 'A' || 'Z' < c {
				return false
			}
		}
	}
	return true
}

// SourcePriority ranks the free geolocation sources by trustworthiness, most
// trusted first. Lower value = more trusted. It is keyed by the exact
// SourceResult.Name values the sources in sources.go set.
//
// consensus uses this ordering to break exact vote-count ties: when two
// candidate answers (country codes or cities) receive the same number of
// votes, the answer contributed by the more trusted source wins, instead of
// an arbitrary lexicographically-smaller string winning by coincidence.
//
// With the current 3-source table, a qualifying tie is unreachable in
// production: breaking a tie AND clearing the confidence threshold
// (MinSources == 2) requires a 2-2 split, i.e. 4 votes, but only 3 sources
// run. (This is why the tie-break tests synthesize a 4-element slice with a
// duplicated source name — a shape locate() cannot actually produce today.)
// The comparator is kept correct and exercised anyway because it starts
// mattering the moment a 4th source is added.
var SourcePriority = map[string]int{
	"ip.pn":     0,
	"freeipapi": 1,
	"ipinfo":    2,
}

// unknownSourceRank is the rank assigned to a source name absent from
// SourcePriority. It is deliberately larger than any real entry so unknown
// sources always lose a tie-break against a known source.
const unknownSourceRank = 1 << 30

// sourceRank returns name's trust rank (lower = more trusted). Unknown or
// empty names get unknownSourceRank so they always lose ties.
func sourceRank(name string) int {
	if rank, ok := SourcePriority[name]; ok {
		return rank
	}
	return unknownSourceRank
}

// displayField picks the human-readable rendering of a winning candidate --
// the country name, the city's display casing, the region name -- from
// whichever contributing source is most trusted.
//
// It exists because these three fields used to resolve by three different and
// mutually inconsistent rules: country name and region were last-writer-wins
// while city display was first-writer-wins, so which rendering survived
// depended on nothing but a source's position in the results slice. With
// ip.pn reporting Region "Colorado" and ipinfo reporting "CO", ipinfo's "CO"
// won purely because it sorts later in `sources` -- the least-trusted source's
// rendering beating the most-trusted one's. That is not cosmetic: the server
// canonicalizes location_name permanently (model.CreateLocation dedupes and
// stores it), so a bad pick is durable.
//
// All three now use the same SourcePriority order that already decides the
// verdict, so the winning code/city and the words shown for it come from the
// same ranking. Ties keep the first offer, which makes the result independent
// of map iteration order.
type displayField struct {
	value map[string]string
	rank  map[string]int
}

func newDisplayField() displayField {
	return displayField{
		value: map[string]string{},
		rank:  map[string]int{},
	}
}

// offer records v as the rendering for candidate c if it is non-empty and
// comes from a strictly more trusted source than the rendering already held.
// Empty values are never recorded: a source that omitted the field cannot
// blank out one that supplied it, however trusted it is.
func (d displayField) offer(c string, v string, rank int) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if held, ok := d.rank[c]; ok && rank >= held {
		return
	}
	d.value[c] = v
	d.rank[c] = rank
}

// get returns the rendering held for c, or "" if no source supplied one.
func (d displayField) get(c string) string {
	return d.value[c]
}

// agreeOnPlace groups the results whose place name (selected by get) agree
// with each other under the placename.go matcher, and returns the largest
// such group -- the set of sources that corroborate one place.
//
// Every member of the returned group matches every other member PAIRWISE,
// which matters because the match relation is not transitive: "Frankfurt"
// matches "Frankfurt am Main" and "Frankfurt Oder", but those two do not
// match each other. Pairwise-matching is equivalent to the group forming a
// chain under the token-prefix order, and a set of token sequences is a chain
// exactly when all of them are prefixes of the longest one -- so building the
// candidate group around each result in turn (everything that prefixes it)
// enumerates every maximal group, in O(n^2) over at most a handful of
// sources.
//
// Results with no tokens (empty or punctuation-only names) never join a
// group: a source that named no place cannot corroborate one that did.
//
// Ties are broken the same way the rest of consensus breaks them -- by
// SourcePriority, most-trusted contributing source first -- and finally by
// position, so the result never depends on map iteration order.
func agreeOnPlace(ok []SourceResult, get func(SourceResult) string) []SourceResult {
	tokens := make([][]string, len(ok))
	for i, r := range ok {
		tokens[i] = PlaceTokens(get(r))
	}

	var best []SourceResult
	bestRank := 0
	for i := range ok {
		if len(tokens[i]) == 0 {
			continue
		}
		var group []SourceResult
		rank := unknownSourceRank
		for j := range ok {
			if tokensPrefixOrEqual(tokens[j], tokens[i]) {
				group = append(group, ok[j])
				if r := sourceRank(ok[j].Name); r < rank {
					rank = r
				}
			}
		}
		if len(best) < len(group) || (len(best) == len(group) && rank < bestRank) {
			best, bestRank = group, rank
		}
	}
	return best
}

// canonicalPlace renders the display name for a group returned by
// agreeOnPlace: the SHORTEST variant in the group, by token count.
//
// The shortest variant is exactly the assertion every source in the group
// supports -- "Frankfurt am Main" when one source said that and another said
// "Frankfurt am Main (Innenstadt I)". Picking a longer one would publish a
// specificity that not every agreeing source confirmed, and the server
// canonicalizes and permanently stores the name it is given. Ties in token
// count are broken by SourcePriority, consistent with how the other display
// fields resolve, and then by position for determinism.
//
// The name is rendered from the winning source's ORIGINAL string (via
// PlaceDisplay, which only drops parentheticals and collapses whitespace),
// never from the normalized tokens, so casing and diacritics survive:
// "Logroño", not "logrono".
func canonicalPlace(group []SourceResult, get func(SourceResult) string) string {
	best, bestN, bestRank := "", 0, 0
	for _, r := range group {
		n := len(PlaceTokens(get(r)))
		if n == 0 {
			continue
		}
		rank := sourceRank(r.Name)
		if best == "" || n < bestN || (n == bestN && rank < bestRank) {
			best, bestN, bestRank = PlaceDisplay(get(r)), n, rank
		}
	}
	return best
}

// consensus computes a ConsensusLocation from successful source results.
// Callers pass only results with OK == true. It does not enforce the quorum
// (Locate does that before calling); with a single result it simply yields a
// non-confident country.
func consensus(ok []SourceResult) ConsensusLocation {
	var loc ConsensusLocation

	// country: plurality over non-empty normalized codes; confident only at >= MinSources.
	// Ties in vote count are broken by the most-trusted contributing source
	// (SourcePriority), falling back to lexicographic order only if ranks also tie.
	countryCounts := map[string]int{}
	countryName := newDisplayField()
	countryRank := map[string]int{}
	countryHasRank := map[string]bool{}
	for _, r := range ok {
		c := normalizeCountry(r.CountryCode)
		if c == "" {
			continue
		}
		countryCounts[c]++
		countryName.offer(c, r.Country, sourceRank(r.Name))
		rank := sourceRank(r.Name)
		if !countryHasRank[c] || rank < countryRank[c] {
			countryRank[c] = rank
			countryHasRank[c] = true
		}
	}
	bestCountry, bestCountryN, bestCountryRank := "", 0, 0
	for c, n := range countryCounts {
		rank := countryRank[c]
		switch {
		case n > bestCountryN:
			bestCountry, bestCountryN, bestCountryRank = c, n, rank
		case n == bestCountryN && rank < bestCountryRank:
			bestCountry, bestCountryRank = c, rank
		case n == bestCountryN && rank == bestCountryRank && c < bestCountry:
			bestCountry = c
		}
	}
	if bestCountryN >= MinSources {
		name := countryName.get(bestCountry)
		if name == "" {
			// No source supplied a human-readable name for the winning code
			// (e.g. ipinfo-only quorum: it returns a code but never a name).
			// Fall back to the ISO-3166-1 table so a confident country isn't
			// submitted with an empty name, which the server rejects. A
			// source-supplied name above always takes priority; this only
			// fires when none was given. countryNameForCode itself degrades
			// to "" for a code outside the table, which is the correct,
			// non-corrupting behavior: leave Country empty rather than
			// invent a placeholder.
			name = countryNameForCode(bestCountry)
		}
		// CountryConfident means "I have a complete, usable country record",
		// exactly as CityConfident means it for the city fields: agreement
		// alone is not enough. The server rejects a submission whose country
		// code is not alpha-2 ("Country code must be alpha-2.") or whose
		// country name is empty ("Missing country."), and neither rejection
		// is cached by the scheduler -- so a provider that produces one is
		// re-probed and re-rejected on every pass, forever, burning a tunnel
		// and three lookups each time. Both shapes are reachable: XK (Kosovo,
		// user-assigned) and the MaxMind-lineage A1/A2/AP are two characters
		// but absent from the ISO table, and normalizeCountry never validates
		// length, so two sources reporting "USA" would otherwise sail through.
		// Degrade to not-country-confident (and leave the fields empty, as
		// the no-majority path does) rather than emit a doomed submission.
		if isAlpha2(bestCountry) && name != "" {
			loc.CountryCode = bestCountry
			loc.Country = name
			loc.CountryConfident = true
		}
	}

	// city: set only if >= 2 sources agree on the city, where "agree" is the
	// place-name match of placename.go (equal, or one a token-prefix of the
	// other) rather than exact normalized string equality. The threshold is
	// unchanged; only the definition of agreement is wider.
	agreeing := agreeOnPlace(ok, func(r SourceResult) string { return r.City })
	// CityConfident requires both city agreement AND a resolved Region: the
	// server rejects any city-confident submission with an empty region,
	// and that rejection kills the whole POST -- including a perfectly good
	// country result. Region is only populated when some source supplied
	// one (never fabricated), so when no agreeing source named a region,
	// degrade cleanly to country granularity instead of submitting an
	// incomplete record: leave City/Region empty and CityConfident false.
	if len(agreeing) >= 2 {
		// The region is resolved among the agreeing sources only, and with
		// the same matcher: it is the same class of problem as the city
		// ("Hesse" vs "Hesse " vs "Hesse (HE)"), and since CityConfident
		// requires a non-empty region, region variants that failed to merge
		// would keep discarding city results even after the city itself
		// started matching. Unlike the city there is no >= 2 threshold --
		// the region has never been voted on, it is carried from whichever
		// agreeing source supplied one -- so a lone region still wins.
		regionGet := func(r SourceResult) string { return r.Region }
		region := canonicalPlace(agreeOnPlace(agreeing, regionGet), regionGet)
		if region != "" {
			loc.City = canonicalPlace(agreeing, func(r SourceResult) string { return r.City })
			loc.Region = region
			loc.CityConfident = true
		}
	}

	// asn: plurality over non-zero ASNs, adopted only at >= MinSources votes.
	// A plurality of one is not a plurality, it is whichever source answered:
	// with three independent free apis, one compromised or simply wrong
	// source would otherwise dictate the ASN and Org for every provider the
	// fleet probes. This is the same bar the country clears, and it fails the
	// same way -- empty rather than wrong.
	//
	// Tie-break note: on an exact vote-count tie this picks the numerically
	// smaller ASN (map iteration order plus "a < bestASN" below), not the
	// most-trusted source as country/city do via SourcePriority. This
	// deviates from the design spec's "0 if none/tie" wording; documenting
	// the deviation here rather than changing established behavior.
	asnCounts := map[int]int{}
	asnOrg := map[int]string{}
	for _, r := range ok {
		if r.ASN == 0 {
			continue
		}
		asnCounts[r.ASN]++
		if r.Org != "" {
			asnOrg[r.ASN] = r.Org
		}
	}
	bestASN, bestASNN := 0, 0
	for a, n := range asnCounts {
		if n > bestASNN || (n == bestASNN && a < bestASN) {
			bestASN, bestASNN = a, n
		}
	}
	if bestASNN >= MinSources {
		loc.ASN = bestASN
		loc.Org = asnOrg[bestASN]
	}

	// net_type flags: corroborated where corroboration is POSSIBLE.
	//
	// These were OR-ed, which made each one a single-source assertion in a
	// record whose country and city both require corroboration: one of three
	// free apis -- compromised, or merely wrong for an afternoon -- could
	// mark Proxy or Hosting on every provider the fleet probes,
	// indistinguishable downstream from a flag all three agreed on.
	//
	// A flat MinSources bar is wrong here though, because the sources are not
	// interchangeable for these fields the way they are for the country. Only
	// ip.pn carries hosting and mobile at all (freeipapi carries proxy;
	// ipinfo carries none), so demanding two votes for hosting made it
	// permanently false -- a silent, total loss of the field rather than a
	// conservative default. The threshold is therefore the corroboration
	// actually available: two votes when two sources can express the flag,
	// one when only one can.
	//
	// The residual risk is explicit rather than hidden: a flag only one
	// source can report is that source's word, and adding the field to a
	// second parser is what raises its bar. Callers that need to know which
	// regime a flag came from must look at the per-source records in Sources.
	loc.Hosting = flagAgreed(ok, func(r SourceResult) (bool, bool) { return r.Hosting, r.Supports.Hosting })
	loc.Proxy = flagAgreed(ok, func(r SourceResult) (bool, bool) { return r.Proxy, r.Supports.Proxy })
	loc.Mobile = flagAgreed(ok, func(r SourceResult) (bool, bool) { return r.Mobile, r.Supports.Mobile })

	return loc
}

// flagAgreed reports one net-type flag's consensus value. get returns the
// flag and whether that source can express it at all.
//
// The threshold is min(MinSources, sources capable of the flag): full
// corroboration where the table supports it, and the single capable source's
// word where it does not -- never a bar no source set can clear. Sources that
// cannot express the flag are not counted as votes against it; they have no
// opinion, and treating silence as a "false" vote would make one capable
// source unable to set a flag that two others simply never mention.
func flagAgreed(ok []SourceResult, get func(SourceResult) (value bool, supported bool)) bool {
	votes, capable := 0, 0
	for _, r := range ok {
		value, supported := get(r)
		if !supported {
			continue
		}
		capable++
		if value {
			votes++
		}
	}
	if capable == 0 {
		return false
	}
	threshold := MinSources
	if capable < threshold {
		threshold = capable
	}
	return votes >= threshold
}
