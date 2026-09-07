package geolocate

import (
	"reflect"
	"testing"
)

func TestPlaceTokens(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   \t\n ", nil},
		{"plain", "Denver", []string{"denver"}},
		{"lowercased", "FRANKFURT AM MAIN", []string{"frankfurt", "am", "main"}},
		{"whitespace collapsed and trimmed", "  Frankfurt   am\tMain  ", []string{"frankfurt", "am", "main"}},

		// Parenthetical reduction. A group is dropped only when >= 2 tokens
		// precede it (a subdivision); otherwise it is kept (a disambiguator).
		{"district suffix dropped after a multi-token name", "Frankfurt am Main (Innenstadt I)", []string{"frankfurt", "am", "main"}},
		{"disambiguator kept after a single token", "Frankfurt (Oder)", []string{"frankfurt", "oder"}},
		{"token count is not whitespace-based", "Frankfurt-am-Main (Innenstadt)", []string{"frankfurt", "am", "main"}},
		{"nested group dropped with its parent", "Foo Bar (baz (qux) quux) end", []string{"foo", "bar", "end"}},
		{"nested group kept with its parent", "Foo (bar (baz) qux) end", []string{"foo", "bar", "baz", "qux", "end"}},
		{"a retained group counts toward later groups", "Frankfurt (Oder) (Altstadt)", []string{"frankfurt", "oder"}},
		{"unclosed paren swallows the tail when dropping", "Frankfurt am Main (Innenstadt", []string{"frankfurt", "am", "main"}},
		{"unclosed paren is kept when retaining", "Frankfurt (Oder", []string{"frankfurt", "oder"}},
		{"stray close paren is ordinary text", "Frankfurt) am Main", []string{"frankfurt", "am", "main"}},
		{"leading parenthetical is kept", "(Innenstadt I)", []string{"innenstadt", "i"}},
		{"empty parenthetical yields no tokens", "()", nil},
		{"unbalanced closers do not underflow", ")))Denver(((", []string{"denver"}},

		// Accent folding. Latin-1 Supplement and Latin Extended-A only; this
		// is an explicit table, not Unicode normalization.
		{"tilde n", "Logroño", []string{"logrono"}},
		{"acute a", "Málaga", []string{"malaga"}},
		{"umlaut u", "Zürich", []string{"zurich"}},
		{"tilde a", "São Paulo", []string{"sao", "paulo"}},
		{"eszett", "Gießen", []string{"giessen"}},
		{"slashed o", "Tromsø", []string{"tromso"}},
		{"latin extended a", "Łódź", []string{"lodz"}},
		{"decomposed input folds the same as composed", "Logroño", []string{"logrono"}},

		// Punctuation becomes a separator.
		{"comma", "Washington, D.C.", []string{"washington", "d", "c"}},
		{"hyphen", "Île-de-France", []string{"ile", "de", "france"}},
		{"apostrophe", "L'Hospitalet", []string{"l", "hospitalet"}},
		{"slash", "Buda/Pest", []string{"buda", "pest"}},
		{"digits kept", "Paris 15", []string{"paris", "15"}},
		{"punctuation only", " - , . / ' ", nil},

		// Non-Latin scripts are left alone rather than mangled: they still
		// compare exactly against another source spelling them the same way.
		{"non-latin passes through", "東京", []string{"東京"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PlaceTokens(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("PlaceTokens(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestPlaceDisplay(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Frankfurt am Main (Innenstadt I)", "Frankfurt am Main"},
		// A retained disambiguator must survive into the stored name.
		{"Frankfurt (Oder)", "Frankfurt (Oder)"},
		{"  Frankfurt  (Oder)  ", "Frankfurt (Oder)"},
		{"  Frankfurt   am  Main  ", "Frankfurt am Main"},
		// Casing and diacritics are preserved: the display name is what gets
		// stored server-side, permanently.
		{"Logroño", "Logroño"},
		{"DENVER", "DENVER"},
		{"Washington, D.C.", "Washington, D.C."},
		{"", ""},
		{"(only a qualifier)", "(only a qualifier)"},
		// A retained group is echoed verbatim even when it holds no tokens.
		// Unreachable from consensus: canonicalPlace never renders a name
		// whose token sequence is empty.
		{"()", "()"},
	}
	for _, c := range cases {
		if got := PlaceDisplay(c.in); got != c.want {
			t.Errorf("PlaceDisplay(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPlaceNamesMatchFrankfurtVariants is the motivating case: the three
// renderings a real probe can produce must all match each other, in both
// directions.
func TestPlaceNamesMatchFrankfurtVariants(t *testing.T) {
	variants := []string{
		"Frankfurt am Main (Innenstadt I)",
		"Frankfurt am Main",
		"Frankfurt",
	}
	for _, a := range variants {
		for _, b := range variants {
			if !PlaceNamesMatch(a, b) {
				t.Errorf("PlaceNamesMatch(%q, %q) = false, want true", a, b)
			}
		}
	}
}

// TestPlaceNamesMatchRejectsSuffixAndSubstring pins the safety property: the
// rule is token-sequence equality or a PROPER TOKEN PREFIX, never an
// arbitrary substring and never a suffix.
func TestPlaceNamesMatchRejectsSuffixAndSubstring(t *testing.T) {
	cases := []struct{ a, b string }{
		// Suffix, not prefix. This is the headline non-match: two very
		// different cities whose names share a trailing token.
		{"York", "New York"},
		{"Orleans", "New Orleans"},
		{"Jersey City", "New Jersey City"},
		// Substring of a token, not a token boundary.
		{"Frank", "Frankfurt"},
		{"Ham", "Hamburg"},
		// Divergent at a token, same length.
		{"San Jose", "San Diego"},
		// Divergent after a shared prefix token.
		{"Frankfurt am Main", "Frankfurt an der Oder"},
		{"Newcastle upon Tyne", "Newcastle under Lyme"},
		// A parenthetical after a SINGLE token is a disambiguator and is
		// retained as tokens, so it can diverge and block the merge.
		// "Frankfurt (Oder)" is a real, different city ~90km from Frankfurt
		// am Main and in a different Land; unconditional stripping would
		// reduce it to "Frankfurt", which then prefixes "Frankfurt am Main"
		// and silently merges the two. This is the case the retention rule
		// exists for.
		{"Frankfurt am Main", "Frankfurt (Oder)"},
		{"Frankfurt (Oder)", "Frankfurt (Main)"},
		{"Frankfurt am Main (Innenstadt I)", "Frankfurt (Oder)"},
	}
	for _, c := range cases {
		if PlaceNamesMatch(c.a, c.b) {
			t.Errorf("PlaceNamesMatch(%q, %q) = true, want false", c.a, c.b)
		}
		if PlaceNamesMatch(c.b, c.a) {
			t.Errorf("PlaceNamesMatch(%q, %q) = true, want false (symmetry)", c.b, c.a)
		}
	}
}

// TestPlaceNamesMatchEmptyMatchesNothing pins that an absent name never
// corroborates anything, including another absent name. Two sources that both
// failed to report a city have not agreed on a city -- if empty matched
// empty, two silent sources would clear the >= 2 threshold and produce a
// "confident" city of "".
func TestPlaceNamesMatchEmptyMatchesNothing(t *testing.T) {
	cases := []struct{ a, b string }{
		{"", ""},
		{"", "Frankfurt"},
		{"Frankfurt", ""},
		{"   ", "Frankfurt"},
		{"   ", "   "},
		{"()", "()"},
		{" - . ", " - . "},
	}
	for _, c := range cases {
		if PlaceNamesMatch(c.a, c.b) {
			t.Errorf("PlaceNamesMatch(%q, %q) = true, want false: an empty name corroborates nothing", c.a, c.b)
		}
	}
}

// TestPlaceNamesMatchAcceptedPrefixConsequences documents the cases the
// prefix rule merges ON PURPOSE. These are not oversights: every source in a
// consensus is describing ONE ip, so a bare prefix from one source is read as
// a less specific description of the same place, not as a different place.
// Because the canonical name is always the SHORTEST variant, a merge like
// this yields the less specific name ("Kansas"), never a specificity no
// source asserted.
func TestPlaceNamesMatchAcceptedPrefixConsequences(t *testing.T) {
	cases := []struct{ a, b, why string }{
		{"Kansas City", "Kansas", "a state name is a prefix of a city name; both describe the same ip, so the shorter reading wins"},
		{"Mexico City", "Mexico", "same shape as Kansas City / Kansas"},
		{"Quebec City", "Quebec", "same shape as Kansas City / Kansas"},
		// A BARE "Frankfurt" still merges with "Frankfurt (Oder)", and this
		// one is unavoidable: a source that wrote only "Frankfurt" supplied
		// nothing to distinguish the two cities, so there is no lexical
		// signal left to act on. It is genuinely ambiguous rather than
		// wrong, and the canonical-shortest rule keeps the published name at
		// "Frankfurt" -- the most any source actually asserted. No further
		// heuristic is added to chase it.
		{"Frankfurt", "Frankfurt (Oder)", "a source that named no qualifier gave nothing to disambiguate with"},
	}
	for _, c := range cases {
		if !PlaceNamesMatch(c.a, c.b) {
			t.Errorf("PlaceNamesMatch(%q, %q) = false, want true (accepted consequence: %s)", c.a, c.b, c.why)
		}
	}
}

// TestPlaceNamesMatchNormalizationInteractions covers agreement that only
// exists after normalization -- the accent, punctuation and case folding
// doing real work across sources that spell the same place differently.
func TestPlaceNamesMatchNormalizationInteractions(t *testing.T) {
	match := []struct{ a, b string }{
		{"Logroño", "logrono"},
		{"Zürich", "ZURICH"},
		{"São Paulo", "Sao Paulo"},
		{"Île-de-France", "Ile de France"},
		{"Frankfurt-am-Main", "Frankfurt am Main"},
		{"Comunidad de Madrid", "comunidad de madrid"},
	}
	for _, c := range match {
		if !PlaceNamesMatch(c.a, c.b) {
			t.Errorf("PlaceNamesMatch(%q, %q) = false, want true", c.a, c.b)
		}
	}

	// A trailing qualifier is a prefix relation and merges; a LEADING
	// qualifier is a suffix relation and does not. "Comunidad de Madrid" vs
	// "Madrid" is the second shape, so region variants of that form still
	// fail to merge -- a known limit of a prefix-only rule, kept because
	// accepting suffixes would also accept "York" ~ "New York".
	if PlaceNamesMatch("Comunidad de Madrid", "Madrid") {
		t.Error("PlaceNamesMatch(\"Comunidad de Madrid\", \"Madrid\") = true; a leading qualifier is a suffix relation and must not match")
	}
}

// TestPlaceNamesMatchAcceptedFalseSplits documents the cost of retaining a
// parenthetical after a single token: names that a human would merge do not
// merge. This is deliberate. The two failure modes are asymmetric -- a false
// merge publishes a wrong location the server stores as canonical and is hard
// to walk back, while a false split only degrades that provider to country
// granularity, which is safe and self-corrects on the next probe -- so a rule
// that can only ever make matching stricter is the right trade.
func TestPlaceNamesMatchAcceptedFalseSplits(t *testing.T) {
	cases := []struct{ a, b, why string }{
		{"Paris (75)", "Paris, France", "the departement number is retained after the single token \"Paris\", so it diverges from \"france\""},
		{"Cambridge (MA)", "Cambridge Massachusetts", "same shape: a retained qualifier that the other source spelled out"},
	}
	for _, c := range cases {
		if PlaceNamesMatch(c.a, c.b) {
			t.Errorf("PlaceNamesMatch(%q, %q) = true, want false (accepted false split: %s)", c.a, c.b, c.why)
		}
	}
}
