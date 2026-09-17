// Package egresshealth checks whether a provider actually carries traffic to
// the real internet, across several independent classes of destination.
//
// All network access goes through an injected *http.Client; this package never
// constructs a client, transport, or dialer. fleetprobe supplies a client whose
// only dial boundary is the selected provider's userspace TUN, with no host
// fallback. A broken tunnel therefore fails the request even when the host has
// ordinary LAN egress. The standalone command's confinement check remains
// defense in depth; correctness does not depend on a special host route.
//
// # Why this exists
//
// Provider reliability scoring on the server is presence-based:
// reliabilityRunningAggSql counts reported time blocks and sums
// 1.0/valid_client_count, and never consults delivered bytes. A provider that
// stays connected 24/7 while blackholing every byte therefore scores perfectly
// and stays selectable. That is not hypothetical -- a mainnet capture showed a
// provider accepting 87 KB and returning 0 bytes while connected = true and
// valid = true.
//
// The geolocation probe (see geolocate/) is not a sufficient answer, because it
// only ever touches one class of destination: three geolocation APIs. A
// provider needs to serve exactly those three hosts to look healthy, and the
// other client-visible failure -- CDNs and large sites rejecting datacenter IP
// ranges -- is invisible to it, since the geolocation APIs do not care where
// the request came from.
//
// # Classes
//
// Destinations are grouped so a PARTIAL failure is diagnosable. "ok=14/26"
// alone says nothing; "dns=4/4 cdn=0/5 site=12/12" says the tunnel carries
// bytes and resolves names but is being refused by content providers, which is
// the datacenter-IP-rejection case -- a completely different fault from a total
// blackhole (ok=0/26), and a different fault again from one flaky destination.
//
// The table deliberately spreads across DIFFERENT operators within each class,
// so a provider that special-cases one vendor's ranges cannot pass a class.
//
// ClassReputation is scored SEPARATELY and deliberately excluded from
// OKCount/Total -- see its doc comment below, which is the one thing in this
// package most likely to be "fixed" into a bug.
//
// # Sampling: the table is large, a run is not
//
// The table is 140 destinations. A run fetches a bounded RANDOM SAMPLE of each
// class rather than the whole thing (see sampleSizes for the arithmetic), so
// coverage accumulates across runs instead of being paid on every one.
//
// This is one code path with one set of constants for every deployment. There
// is no "small table for mainstream, big table for beta" switch and there must
// not be one: a knob that only one environment exercises is how a gap goes
// unnoticed here -- the untested branch is the one that runs against 100k
// providers.
//
// Sampling also buys a property a fixed table cannot have, and it is a security
// property rather than a cost one. A provider cannot know which destinations it
// will be asked for, because the draw happens at run time from the prober's own
// randomness. Whitelisting a handful of well-known hosts -- which defeats any
// fixed table, and defeated the fixed nine-entry table this descends from --
// now fails: to pass reliably a provider has to carry traffic to essentially
// the whole table, which is the thing being measured. That is a reason to
// prefer sampling a wide table over simply carrying a narrow one.
//
// # DNS
//
// The dns class is seven DNS-over-HTTPS endpoints. It is not, and cannot
// currently be, a test of resolvers as such: the owner's list names 23 bare
// resolver ADDRESSES (8.8.8.8, 1.1.1.1, ...), and a resolver is queried over
// UDP/53 or TCP/53, which this package has no way to reach -- the tunnel is
// exposed to it as an *http.Client and nothing else. Genuine resolver coverage
// needs a UDP path through the tunnel, which is a different piece of work; the
// bare-IP rows are ignored here rather than fetched over http, which would test
// something else entirely and pass or fail for reasons unrelated to resolution.
//
// What the DoH entries do prove is that a name was resolved END TO END through
// the tunnel, because every one of them parses its answer (see verifyDNSJSON).
// A captive portal answers 200 with bytes; only an answer section proves
// resolution.
//
// # Ambiguity this cannot resolve on its own
//
// Name resolution is a shared precondition: the tunnel resolves every hostname
// through in-tunnel DoH (connect's DefaultDnsResolverSettings, which uses
// 1.1.1.1, 8.8.8.8, 9.9.9.9 and 208.67.222.222), and providertunnel
// deliberately disables the off-tunnel fallback. So a run that comes back 0/26
// is "this provider carried nothing useful", which covers both a blackhole and
// an in-tunnel DoH failure. The per-check Err strings are what separate them:
// a resolution failure names the lookup, a blackhole times out on the request.
// Do not read 0/26 as proof of a blackhole without them.
//
// # Byte budget
//
// Each check is a small GET whose body read is capped -- per destination via
// Destination.MaxBytes, and never above MaxBodyBytes, which is 1024 bytes.
//
// Fetching the whole table at that cap would cost 128 KiB per provider per run
// (the same table fetched UNCAPPED was measured at 36,960 KiB, because several
// front pages are 1.5-2.4 MB). 128 KiB is affordable for beta's ~40 providers
// and is ~12 GB per pass at 100k providers, which is far outside the budget
// this rides -- so the run samples, and the SAMPLE is what the budget is
// computed on. The arithmetic is on sampleSizes and is asserted by
// TestWorstCaseBytesPerRunFitsTheBudget:
//
//	dns           4 x  768 =  3072
//	connectivity  5 x  256 =  1280
//	cdn           5 x 1024 =  5120
//	site         12 x 1024 = 12288
//	                        ------
//	health                 = 21760
//	reputation    4 x 1024 =  4096
//	                        ------
//	per run                = 25856 bytes = 25.25 KiB
//
// That is below the 33.25 KiB of the 31-entry fixed table this replaces, from a
// table four and a half times wider. Adding TLS handshakes, request/response
// headers and the DoH lookups behind them, a run stays well under 128 KiB.
//
// Where it is honored, a Range header holds the larger destinations to ~1 KiB
// on the wire. Many hosts IGNORE it -- measured on this table: www.wikipedia.org,
// www.atlassian.com, cloud.google.com, apnews.com and www.baidu.com all
// returned 200 and the whole asset, and jsDelivr and BootstrapCDN did the same
// in an earlier round -- so the header is an optimisation, and io.LimitReader
// is what actually bounds the cost. A server that ignores Range can still put
// up to one TCP receive window in flight before the capped read closes the
// body, which is the one place these figures can be exceeded on the wire.
//
// This rides the same budget as the server's active bandwidth probe, which
// spends model.MaxProviderBandwidthBytesPerProbe = 16 MiB per probe (8
// parallel streams of 2 MiB -- see bandwidth.StreamCount for why one stream
// measured the congestion window rather than the provider). A full
// egress-health run is under 0.2% of one bandwidth probe.
package egresshealth

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Class groups destinations so a partial failure is diagnosable: a provider
// that serves DNS but fails every CDN is the datacenter-IP-blocking case,
// which is a different fault from a total blackhole.
type Class string

const (
	ClassDNS Class = "dns"
	// ClassConnectivity is the purpose-built captive-portal-detection endpoints
	// every operating system already ships with, plus the echo services that
	// answer with the exit address. They are unauthenticated, carry no anti-bot
	// machinery, and answer in tens of bytes -- the cheapest useful signal in
	// the table, and the class least likely to fail for a reason that has
	// nothing to do with the provider.
	ClassConnectivity Class = "connectivity"
	// ClassCDN is CDN edges, distribution mirrors and bulk-download hosts: the
	// operators whose business is serving static bytes. This is the class that
	// fails when a provider's egress range is on a CDN blocklist.
	ClassCDN Class = "cdn"
	// ClassSite is ordinary web properties -- search, social, video, commerce,
	// news, reference, developer infrastructure, and the regional properties
	// that carry the same traffic outside the US and EU.
	//
	// The regional entries (qq.com, taobao, vk, naver, globo, ...) are
	// deliberately NOT a class of their own, even though the source list groups
	// them that way. A "regional" class would fail on healthy providers for
	// geographic reasons -- an exit in one country reaching another country's
	// properties slowly or not at all -- which is the ClassReputation trap
	// reintroduced INSIDE the health score. Mixed into site, they widen the
	// operator spread without inventing a verdict the data cannot support.
	ClassSite Class = "site"

	// ClassReputation measures something the other classes do not, and is
	// EXCLUDED FROM THE HEALTH SCORE ON PURPOSE. Do not fold it into
	// Result.OKCount/Total. Six of its eight entries were measured refusing a
	// datacenter IP outright -- 403, 401 -- in four consecutive runs from a
	// hosted host, and again when this table was built. On a residential or
	// cellular exit those same endpoints return clean. So a
	// failure here says "this exit is treated as a datacenter by bot-management
	// vendors", which is genuinely useful (a provider that passes is more useful
	// to a real user, because that is what the user will hit) but is NOT a
	// statement that the provider is broken. Scoring it would make every hosted
	// provider read as degraded and destroy the signal the health classes carry.
	//
	// One caveat that constrains how far this can be read, recorded because it
	// is measured rather than assumed. Three observations of www.reddit.com from
	// the SAME host and IP, within a day:
	//
	//	curl, default user-agent          -> 403 (4/4 runs)
	//	the Go prober through a provider  -> 200
	//	curl, this package's UserAgent    -> 206
	//
	// Same address, three different clients, three different answers. That is
	// TLS/client fingerprinting at least as much as it is IP reputation. So a
	// reputation failure is evidence about the CLIENT-AND-IP PAIR, not about the
	// address alone, and this class needs field data across many providers
	// before anyone treats it as a clean IP-quality score. It is a diagnostic
	// under observation, not a metric.
	//
	// Two entries in it do not currently discriminate, and both are recorded on
	// the entries themselves so a log line is not misread: stackoverflow answers
	// 302 to everyone (a zero-body issue, never an ip refusal), and ecosia's
	// answer differed between the staged runs and the one that built this table.
	ClassReputation Class = "reputation"
)

// Classes is the declared order the SCORED classes are reported in.
// Result.ByClass is a map, so iterating it directly would render a different
// summary line on every pass; every ordered rendering goes through this slice
// instead.
//
// ClassReputation is deliberately absent: it is not part of the health score
// and is reported on its own (Result.Reputation). See its doc comment.
var Classes = []Class{ClassDNS, ClassConnectivity, ClassCDN, ClassSite}

// unscoredClasses are the classes kept out of Result.OKCount/Total/ByClass.
//
// A class is scored unless it is named here, so a class added later lands in
// the health score by default -- which is the safe direction: a new class that
// should not be scored is a visible number nobody can miss, whereas a health
// class silently omitted from the score would be a signal quietly turned off.
var unscoredClasses = map[Class]bool{ClassReputation: true}

// scored reports whether a class counts towards the health score.
func scored(c Class) bool { return !unscoredClasses[c] }

// sampleSizes is how many destinations of each class one run draws. It is a
// package constant, identical in every deployment -- see the package comment on
// why there is no per-environment knob.
//
// Two constraints fix these numbers, and it is worth recording which one binds.
//
// The BYTE budget: at the 1024-byte cap a run may spend about 33 KiB per
// provider (what the 31-entry fixed table cost), which would buy ~33
// destinations. The arithmetic for the sizes below is on the package comment
// and comes to 25.25 KiB.
//
// The WALL-CLOCK budget binds first, and is why the sizes stop short of what
// the bytes would allow: a whole run has to fit in one -probe-timeout, which
// means ceil(n/DefaultConcurrency) * DefaultPerRequestTimeout <= DefaultBudget.
// At n = 30 that is ceil(30/6) = 5 rounds x 10s = 50s against a 60s budget.
// Raising site to 18 would spend the spare bytes and put the run at 6 rounds =
// 60s, with no margin for a slow round. Bytes are cheap here; a probe that
// overruns its deadline charges a healthy provider with a blackhole.
//
// THREE IS THE FLOOR for any class, and none of these is below four. A class
// verdict has to separate one flaky endpoint from a class-wide fault: at 1 the
// class is a single destination wearing a class name, at 2 one flake is half
// the class and cdn=1/2 says nothing, and at 3 "cdn=0/3" means three
// independently operated endpoints all refused in the same run -- which is a
// statement. The sizes above the floor buy spread rather than certainty: dns
// draws 4 of 7 so a run usually spans more than one jurisdiction, and site
// draws 12 because it is the widest pool and its verdict would otherwise rest
// on the narrowest evidence.
//
// Coverage is a RATE, not a promise: site draws 12 of 93, so a given site
// destination is asked for on about one run in eight. That is not "the table is
// covered in eight runs" -- drawing 12 at a time from 93 until every entry has
// been seen takes on the order of 40 runs (93/12 * H(93) ~= 40). What
// accumulates quickly is fleet-wide coverage, because every provider draws
// independently.
//
// A class with no entry here is probed WHOLE. That is the safe direction: a
// class added to the table without a sample size costs visible bytes rather
// than silently never being probed.
var sampleSizes = map[Class]int{
	ClassDNS:          4,
	ClassConnectivity: 5,
	ClassCDN:          5,
	ClassSite:         12,
	ClassReputation:   4,
}

// Expect declares what "success" means for one destination. The default,
// ExpectBody, is the original rule and the reason this check catches
// blackholes; ExpectStatus exists for the endpoints where an empty body is the
// correct answer.
type Expect int

const (
	// ExpectBody requires a 2xx AND a non-empty body. This is the default (the
	// zero value) and must stay that way: a status line with no data behind it
	// is exactly what a blackholing provider produces, so a 200 with an empty
	// body is a FAILURE. TestEmptyBodyIs200Failure guards it.
	ExpectBody Expect = iota
	// ExpectStatus requires exactly Destination.Status and permits an empty
	// body. It exists because 21 of the 143 endpoints measured from a real
	// datacenter host are reachable while legitimately returning zero bytes --
	// every generate_204 connectivity check, and many 3xx redirects -- and the
	// ExpectBody rule would score all of them as failures.
	//
	// Note that this is STRICTER than ExpectBody about the status, not looser:
	// the status must match exactly. A provider that synthesizes a bare 200 does
	// not pass an ExpectStatus 204 destination. Relaxing this to "any 2xx" would
	// turn the class into a hole in the blackhole rule.
	//
	// It is still the WEAKER contract in one respect that matters, and no entry
	// should take it without cause: a bare status line proves only that
	// something answered, while a body proves bytes crossed. That is why a 4xx
	// is never declared here (a refusal must stay a failure), and why a
	// destination that could be pointed at a url returning a real body is
	// pointed there instead of being declared.
	ExpectStatus
	// ExpectReachable accepts ANY 2xx or 3xx, with or without a body. It exists
	// for consumer sites that redirect based on the CLIENT'S GEOGRAPHY, which
	// this probe sees from a different exit country on every provider.
	//
	// Measured: microsoft.com answers 206/1024B to a datacenter host in the US
	// and in Germany, but 302/0B through 40 of 40 provider tunnels -- a locale
	// redirect keyed on the exit ip. Declaring a fixed status for such a
	// destination is impossible (the status is a function of where the provider
	// exits) and pointing it at robots.txt only moves the problem, because that
	// redirects too.
	//
	// This is the weakest contract and must stay confined to ClassSite, where
	// the question being asked is "did the provider carry my request to this
	// host and bring back a valid HTTP response" -- which is exactly the
	// "basic functionality" bar. It does NOT weaken the blackhole rule: a
	// blackholing provider returns no response at all, so it fails this too.
	// A 4xx/5xx is still a failure here, so a refusal stays a refusal.
	ExpectReachable
)

// Destination is one endpoint to check.
type Destination struct {
	Name  string
	Class Class
	URL   string
	// Headers are sent with the request, and exist because destinations cannot
	// be checked without them: cloudflare-dns.com answers 400 to the DoH JSON GET
	// form without an Accept header, and the larger assets need a Range header to
	// keep them from putting more than a couple of KiB on the wire. See also
	// UserAgent, which every request carries.
	Headers map[string]string
	// Expect declares the success contract. The zero value is ExpectBody.
	Expect Expect
	// Status is the required status code, and is only read when Expect is
	// ExpectStatus. Leaving it zero there is a misconfiguration and is reported
	// as a failed check rather than silently accepting anything.
	Status int
	// MaxBytes caps the body read for this destination. Zero means MaxBodyBytes,
	// and a value above MaxBodyBytes is clamped to it -- the package-level cap is
	// the one documented in the byte budget and cannot be raised per entry.
	MaxBytes int
	// Verify optionally proves the body is what the destination is supposed to
	// serve, and is the answer to a class of failure a status code cannot see: a
	// captive portal or an interception box happily returns 200 with a body.
	// Only parsing it proves the request was actually served by whom it was
	// addressed to. It runs after the status/body rules, on the (capped) body.
	Verify func(body []byte) error
}

// MaxBodyBytes is the ceiling on any single body read, and the clamp on
// Destination.MaxBytes. It is a cap on the READ, applied with io.LimitReader: a
// hostile or merely huge response cannot blow the byte budget documented on the
// package -- www.canva.com answers a 403 with 1.4 MB and apnews.com a 200 with
// 2.3 MB.
//
// It is 1024 bytes, down from 4096. Nothing in the table needs more: the point
// of a read is that bytes arrived and, where Verify is set, that they parse,
// and every verifier in this package works on far less than a kilobyte. Hitting
// the cap is NOT by itself a signal that anything is wrong -- most destinations
// serve far more than this when healthy.
const MaxBodyBytes = 1024

// rangeFirst1KiB is the Range header sent with every body-bearing destination
// outside the two classes that are small by construction. Where it is honored
// the response is a 206 of ~1 KiB instead of the whole asset; where it is
// ignored the response is a 200 and the capped read applies. It is an
// optimisation on the WIRE cost, never the bound -- see the package comment for
// the hosts measured ignoring it.
const rangeFirst1KiB = "bytes=0-1023"

// acceptDNSJSON is the Accept header for the DoH JSON GET form. Cloudflare
// answers 400 without it. The others serve JSON with no header at all; sending
// it is harmless and keeps the seven entries identical in shape.
const acceptDNSJSON = "application/dns-json"

// dnsQuery is the query every DoH destination asks. example.com is an IANA
// reserved name that will not disappear, and its A record is short.
const dnsQuery = "?name=example.com&type=A"

// Per-class read caps. They are sized just above the largest response measured
// from each class, so the byte budget on the package is real arithmetic rather
// than a hope.
const (
	maxDNSBytes          = 768  // largest measured: doh.dns.sb, 579 B (it returns DNSSEC records)
	maxConnectivityBytes = 256  // largest measured that must PARSE: captive.apple.com, 69 B
	maxAssetBytes        = 1024 // = MaxBodyBytes; everything else
)

// UserAgent identifies this probe to every destination. It is deliberately
// descriptive rather than a browser impersonation: these are other people's
// servers, and an automated client that will not say who it is has no business
// on them.
//
// It is also load-bearing, not courtesy. Go's default "Go-http-client/1.1" is
// refused outright by Wikimedia's robot policy -- measured, not assumed: the
// same URL answered 403 `Please set a user-agent and respect our robot policy`
// under the default agent and 200 under this one, from the same host in the
// same minute. A destination that fails for every provider is not a signal, it
// is noise that would read as site=11/12 across the entire fleet forever.
//
// It also demonstrably changes what ClassReputation measures -- see that
// class's comment, where the same host got 403 under curl's default agent and
// 206 under this one.
const UserAgent = "urnetwork-egress-prober/0.1 (+https://github.com/urnetwork/operator-proxy; operator egress health probe)"

// destinations is the production table: the owner's curated 159-row list,
// minus the rows that cannot be checked over an *http.Client, plus the seven
// DoH endpoints. A run does not fetch it -- see sampleSizes.
//
// Every URL is https and on the default port 443. That is a hard requirement,
// not a coincidence -- the confinement self-check dials one fixed port
// (cmd/egress-prober's confinementPort), so a destination on any other port
// would silently fall outside the check. TestEveryDestinationIsHTTPSOn443
// enforces it.
//
// Every entry was measured from a datacenter host with this package's
// UserAgent, and its contract is what that measurement says: a 200 with a body
// takes the default ExpectBody rule, and 202/204/3xx declare their status. The
// rules the measurements forced, in the order they matter:
//
//   - A 4xx or 5xx is NEVER declared with ExpectStatus. Six reputation entries
//     answer 403/401 from a datacenter exit; declaring those would convert the
//     class's entire signal into a pass.
//
//   - A 200 with a ZERO-LENGTH body cannot be declared either, because it is
//     the blackhole signature itself. Two endpoints measured that way
//     (d1.awsstatic.com and cachefly.cachefly.net's bare host); both are
//     re-pointed at a url on the same operator that serves a real body, and
//     neither is whitelisted by status. See their entries.
//
//   - A destination whose STATUS is not stable cannot be declared, and this is
//     not hypothetical. Three of the owner's 21 zero-body endpoints answered
//     differently when this table was built, from the same host and address
//     days later: netflix 302 -> 200, cnn 302 -> 200, hulu 302 -> 301. A
//     fourth (timesofindia) went the other way, answering 301-with-no-body
//     where the staged run had a body. Those four are re-pointed at
//     /robots.txt, which is a real body and does not move. The exits that will
//     actually run this are providers in arbitrary countries, so a
//     geography-dependent redirect status is a false failure waiting to
//     happen. The rest of the zero-body list is declared as measured, per the
//     owner's instruction.
//
//   - Redirects are declared, never chased: the production client refuses to
//     follow them (providertunnel's CheckRedirect), which is what makes a 3xx
//     an answer about THIS url rather than about wherever it pointed.
//
// Other choices worth recording, because the obvious pick was wrong in a way
// only measurement showed:
//
//   - The nine http:// rows in the list are here as https, all of them verified
//     answering the same status over TLS (the five generate_204 endpoints, the
//     three fixed-text portal checks, archive.ubuntu.com). A plaintext
//     destination is not an option: it could be forged by the provider on the
//     path, which is precisely the party under test. Two rows could not survive
//     that: speedtest.tele2.net has no https listener at all (measured: no
//     connection), and the "Example.com Plain HTTP" row duplicates the https
//     one. Both are dropped.
//
//   - ifconfig.me is asked for /ip, not /. The bare host serves an HTML page to
//     anything that does not look like curl -- measured, 10915 bytes of it --
//     and /ip always answers with the address, which is what verifyIPText can
//     actually prove.
//
//   - one.one.one.one and speed.cloudflare.com are in ClassSite rather than
//     ClassConnectivity, where the source list files them. They answer with an
//     ordinary web page rather than a fixed portal-detection token, so they
//     cannot carry this class's Verify contract, and a connectivity entry
//     without one would pass for a captive portal.
//
//   - dns.alidns.com serves the JSON form on /resolve ONLY. Its /dns-query path
//     answers `400 no 'dns' query parameter found` -- it is wire-format only.
//     doh.dns.sb is the mirror image: /dns-query serves JSON, /resolve is a 301.
//     The path is not interchangeable between operators and cannot be guessed.
//
//   - Quad9, OpenDNS, CleanBrowsing, Mullvad and Control D were all rejected as
//     DoH entries. Quad9 and Mullvad serve only RFC 8484 wire format on 443
//     (400 to a JSON GET) and Quad9's JSON API is on port 5053, which breaks the
//     443-only rule above; Control D answers 200 with a non-JSON body, which is
//     precisely the shape Verify exists to reject.
//
//   - Operators repeat inside a class, and that is tolerated here where the
//     narrow table refused it: connectivity carries three Google-operated
//     generate_204 hostnames and three Cloudflare-operated endpoints, because
//     the owner's list carries them and dropping them would narrow the pool a
//     sample is drawn from. What protects the class is the draw: five of
//     fourteen, chosen per run, so no single operator can be relied on to
//     appear. Do not read "14 destinations" as "14 operators".
var destinations = []Destination{
	// DNS-over-HTTPS, JSON GET form, SEVEN distinct operators including two
	// Chinese ones (dns.alidns.com, doh.pub) for deliberate jurisdictional
	// diversity: a provider whose upstream filters western resolvers, or the
	// reverse, shows up as a partial class rather than a clean pass. A provider
	// that blocks DoH breaks name resolution for every client that uses it.
	//
	// Every entry carries Verify: a 200 with bytes is not proof that a name was
	// resolved, because a captive portal or an interception box returns exactly
	// that. Only a parseable answer is. No Range header: these bodies are small
	// and a truncated one would not parse.
	{
		Name:     "cloudflare-doh",
		Class:    ClassDNS,
		URL:      "https://cloudflare-dns.com/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "google-doh",
		Class:    ClassDNS,
		URL:      "https://dns.google/resolve" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "adguard-doh",
		Class:    ClassDNS,
		URL:      "https://dns.adguard-dns.com/resolve" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "dnssb-doh",
		Class:    ClassDNS,
		URL:      "https://doh.dns.sb/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "nextdns-doh",
		Class:    ClassDNS,
		URL:      "https://dns.nextdns.io/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "alidns-doh",
		Class:    ClassDNS,
		URL:      "https://dns.alidns.com/resolve" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "dnspod-doh",
		Class:    ClassDNS,
		URL:      "https://doh.pub/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	// Connectivity checks: the endpoints operating systems use to detect captive
	// portals, plus the echo services that answer with the exit address. None is
	// authenticated, none is behind anti-bot machinery, and all of them answer in
	// well under 256 bytes.
	//
	// The generate_204 entries are the reason Expect exists: 204 with no body is
	// the CORRECT answer, and the ExpectBody rule would have scored all of them
	// as failures. They are also the strictest entries in the table -- an exact
	// status match, so a provider that synthesizes a bare 200 fails them.
	//
	// Every body-bearing entry carries Verify, for the captive-portal case these
	// endpoints were literally designed to detect: a portal returns 200 with a
	// login page, which is non-empty and would otherwise pass. That rule is what
	// moved one.one.one.one and speed.cloudflare.com out of this class -- they
	// answer with an ordinary page there is nothing fixed to check.
	//
	// No Range header anywhere here: these bodies are smaller than the cap
	// already, and a 206 would buy nothing.
	{
		Name:     "google-generate-204",
		Class:    ClassConnectivity,
		URL:      "https://www.google.com/generate_204",
		Expect:   ExpectStatus,
		Status:   204,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "google-connectivitycheck",
		Class:    ClassConnectivity,
		URL:      "https://connectivitycheck.gstatic.com/generate_204",
		Expect:   ExpectStatus,
		Status:   204,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "gstatic-204",
		Class:    ClassConnectivity,
		URL:      "https://www.gstatic.com/generate_204",
		Expect:   ExpectStatus,
		Status:   204,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "apple-captive-portal",
		Class:    ClassConnectivity,
		URL:      "https://captive.apple.com/hotspot-detect.html",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("Success"),
	},
	{
		Name:     "ubuntu-connectivity-check",
		Class:    ClassConnectivity,
		URL:      "https://connectivity-check.ubuntu.com",
		Expect:   ExpectStatus,
		Status:   204,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "firefox-detectportal",
		Class:    ClassConnectivity,
		URL:      "https://detectportal.firefox.com/success.txt",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("success"),
	},
	{
		Name:     "gnome-nm-check",
		Class:    ClassConnectivity,
		URL:      "https://nmcheck.gnome.org/check_network_status.txt",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("online"),
	},
	{
		Name:     "cloudflare-cp-204",
		Class:    ClassConnectivity,
		URL:      "https://cp.cloudflare.com/generate_204",
		Expect:   ExpectStatus,
		Status:   204,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "cloudflare-trace",
		Class:    ClassConnectivity,
		URL:      "https://1.1.1.1/cdn-cgi/trace",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("ip="),
	},
	{
		Name:     "aws-checkip",
		Class:    ClassConnectivity,
		URL:      "https://checkip.amazonaws.com",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyIPText,
	},
	{
		Name:     "ifconfig-me",
		Class:    ClassConnectivity,
		URL:      "https://ifconfig.me/ip",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyIPText,
	},
	{
		Name:     "icanhazip",
		Class:    ClassConnectivity,
		URL:      "https://icanhazip.com",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyIPText,
	},
	{
		Name:     "ipify",
		Class:    ClassConnectivity,
		URL:      "https://api.ipify.org",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyIPText,
	},
	// The list's ipinfo row is NOT here, and the reason is structural rather
	// than about the endpoint: ipinfo.io is a PINNED geolocation source
	// (geolocate/sources.go), and the health destinations are deliberately
	// reached unpinned. A host that is both would either weaken the pin or make
	// a routine leaf rotation read as the provider blackholing a destination.
	// cmd/egress-prober's TestEgressHealthDestinationsAreNotPinned enforces it.
	// The class keeps four other echo services.
	{
		Name:     "example-com-https",
		Class:    ClassConnectivity,
		URL:      "https://example.com",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("Example Domain"),
	},

	// Content delivery: CDN edges, distribution mirrors and bulk-download hosts.
	// Eighteen destinations across Cloudflare, Fastly, jsDelivr, unpkg, Google,
	// Microsoft, CloudFront, KeyCDN, CDN77, Sucuri, CacheFly, OVH and five OS
	// distribution mirrors. This is the class that fails when a provider's egress
	// range sits on a CDN blocklist.
	//
	// The four asset urls (cdnjs, googleapis, jsdelivr, sdk.amazonaws) are
	// version-pinned on purpose -- an unversioned url would move under us -- with
	// the tradeoff that if a vendor ever prunes one it becomes a permanent 404
	// and a permanent false failure. If one named entry fails across the whole
	// fleet while its class passes, suspect the URL before suspecting the
	// providers. They are asset urls rather than front pages because a CDN entry
	// should prove the EDGE serves bytes, which a marketing page fronted by the
	// same CDN does not do as directly.
	{
		Name:     "cloudflare-cdn",
		Class:    ClassCDN,
		URL:      "https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "cloudflare-sized-1kb",
		Class:    ClassCDN,
		URL:      "https://speed.cloudflare.com/__down?bytes=1024",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "fastly",
		Class:    ClassCDN,
		URL:      "https://www.fastly.net",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "jsdelivr-fastly-mirror",
		Class:    ClassCDN,
		URL:      "https://fastly.jsdelivr.net/npm/normalize.css@8.0.1/normalize.min.css",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "unpkg",
		Class:    ClassCDN,
		URL:      "https://unpkg.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "google-hosted-libraries",
		Class:    ClassCDN,
		URL:      "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "microsoft-azure-cdn",
		Class:    ClassCDN,
		URL:      "https://ajax.aspnetcdn.com",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		// d1.awsstatic.com, which the list names, answered 200 with a ZERO-LENGTH
		// body on every measurement -- indistinguishable from the blackhole
		// signature, so it cannot be judged by status and must not be
		// whitelisted into one. Its /robots.txt answers 403. This is the same
		// operator (CloudFront) on the url the previous table measured serving a
		// real body, with Range honored (206, 1024 bytes).
		Name:     "amazon-cloudfront",
		Class:    ClassCDN,
		URL:      "https://sdk.amazonaws.com/js/aws-sdk-2.1691.0.min.js",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "keycdn",
		Class:    ClassCDN,
		URL:      "https://www.keycdn.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "cdn77",
		Class:    ClassCDN,
		URL:      "https://www.cdn77.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// Re-pointed at robots.txt: the bare host IGNORES Range and returns
		// 399,407 B. Measured on the beta fleet it was the single largest source
		// of failures (14 of 40 providers) -- not because those providers were
		// unhealthy, but because moving 390 KB inside the per-request timeout is
		// a bandwidth test wearing a health test's clothes. robots.txt honors
		// Range (206, 24 B).
		Name:     "sucuri-cdn",
		Class:    ClassCDN,
		URL:      "https://www.sucuri.net/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// The list's bare host answered 200 with a zero-length body. CacheFly's own
		// test asset exists to be fetched and honors Range (206, 1024 bytes), so
		// the 10 MB behind it never leaves their edge.
		Name:     "cachefly",
		Class:    ClassCDN,
		URL:      "https://cachefly.cachefly.net/10mb.test",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "ovh-proof-eu",
		Class:    ClassCDN,
		URL:      "https://proof.ovh.net",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "kernel-org-mirrors",
		Class:    ClassCDN,
		URL:      "https://mirrors.kernel.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "debian-cdn",
		Class:    ClassCDN,
		URL:      "https://deb.debian.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "ubuntu-archive-plain-http",
		Class:    ClassCDN,
		URL:      "https://archive.ubuntu.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "alpine-cdn",
		Class:    ClassCDN,
		URL:      "https://dl-cdn.alpinelinux.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "fedora-downloads",
		Class:    ClassCDN,
		URL:      "https://dl.fedoraproject.org",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},

	// Ordinary web properties: search, social, video, commerce, developer
	// infrastructure, news, reference, productivity, gaming, and the regional
	// properties that carry the same traffic outside the US and EU. site=0/12
	// means the tunnel is not carrying ordinary web traffic at all.
	//
	// Chosen for availability rather than for discrimination -- every one of them
	// answered on four consecutive runs from a datacenter host, and the
	// "rejects datacenter ranges" role this class used to carry has moved to
	// ClassReputation, where it is not scored.
	//
	// The 3xx entries here declare the status they were measured answering. Read
	// the rule on the table above before adding another: a declared status is
	// weaker evidence than a body, and a status that varies by the exit's
	// geography is not declarable at all.
	{
		Name:     "cloudflare-one-one-one-one",
		Class:    ClassSite,
		URL:      "https://one.one.one.one",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "cloudflare-speed-test",
		Class:    ClassSite,
		URL:      "https://speed.cloudflare.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "google",
		Class:    ClassSite,
		URL:      "https://www.google.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "bing",
		Class:    ClassSite,
		URL:      "https://www.bing.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "yahoo",
		Class:    ClassSite,
		URL:      "https://www.yahoo.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "duckduckgo",
		Class:    ClassSite,
		URL:      "https://duckduckgo.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "baidu",
		Class:    ClassSite,
		URL:      "https://www.baidu.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "yandex",
		Class:    ClassSite,
		URL:      "https://yandex.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "facebook",
		Class:    ClassSite,
		URL:      "https://www.facebook.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "instagram",
		Class:    ClassSite,
		URL:      "https://www.instagram.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "twitter-x",
		Class:    ClassSite,
		URL:      "https://x.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "linkedin",
		Class:    ClassSite,
		URL:      "https://www.linkedin.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "tiktok",
		Class:    ClassSite,
		URL:      "https://www.tiktok.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "pinterest",
		Class:    ClassSite,
		URL:      "https://www.pinterest.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "snapchat",
		Class:    ClassSite,
		URL:      "https://www.snapchat.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "discord",
		Class:    ClassSite,
		URL:      "https://discord.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "telegram",
		Class:    ClassSite,
		URL:      "https://telegram.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "whatsapp",
		Class:    ClassSite,
		URL:      "https://www.whatsapp.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "mastodon",
		Class:    ClassSite,
		URL:      "https://mastodon.social",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "bluesky",
		Class:    ClassSite,
		URL:      "https://bsky.app",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "youtube",
		Class:    ClassSite,
		URL:      "https://www.youtube.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// Re-pointed, and this is the finding that justifies the rule above: the
		// staged measurement recorded 302-with-no-body four times, and this host
		// measured 200 with 3.2 MB days later. Same host, same address. A status
		// that flips like that cannot be declared, and the exit that matters here
		// is a provider's, in an arbitrary country. robots.txt is 3790 bytes of
		// real body and does not move.
		Name:     "netflix",
		Class:    ClassSite,
		URL:      "https://www.netflix.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "twitch",
		Class:    ClassSite,
		URL:      "https://www.twitch.tv",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "vimeo",
		Class:    ClassSite,
		URL:      "https://vimeo.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// hulu answers 302-with-empty-body on BOTH the bare host and
		// /robots.txt, so it can never satisfy ExpectBody. Declared as the
		// redirect it actually is. Measured on the beta fleet: 4 of 40
		// providers failed on this entry alone before the fix.
		// Measured 302 from one vantage but 301 through provider tunnels: the
		// exact status depends on where the client exits, so it cannot be
		// declared. Reachability is the question this class actually asks.
		Name:     "hulu",
		Class:    ClassSite,
		URL:      "https://www.hulu.com",
		Expect:   ExpectReachable,
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "disney",
		Class:    ClassSite,
		URL:      "https://www.disneyplus.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "spotify",
		Class:    ClassSite,
		URL:      "https://open.spotify.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "soundcloud",
		Class:    ClassSite,
		URL:      "https://soundcloud.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "dailymotion",
		Class:    ClassSite,
		URL:      "https://www.dailymotion.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "amazon",
		Class:    ClassSite,
		URL:      "https://www.amazon.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "ebay",
		Class:    ClassSite,
		URL:      "https://www.ebay.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "walmart",
		Class:    ClassSite,
		URL:      "https://www.walmart.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "alibaba",
		Class:    ClassSite,
		URL:      "https://www.alibaba.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "aliexpress",
		Class:    ClassSite,
		URL:      "https://www.aliexpress.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "target",
		Class:    ClassSite,
		URL:      "https://www.target.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "shopify",
		Class:    ClassSite,
		URL:      "https://www.shopify.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// 206/1024B to a datacenter host, 302/0B through all 40 provider
		// tunnels: a locale redirect keyed on the exit ip. See ExpectReachable.
		Name:     "microsoft",
		Class:    ClassSite,
		URL:      "https://www.microsoft.com",
		Expect:   ExpectReachable,
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "apple",
		Class:    ClassSite,
		URL:      "https://www.apple.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "github",
		Class:    ClassSite,
		URL:      "https://github.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "github-api",
		Class:    ClassSite,
		URL:      "https://api.github.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "gitlab",
		Class:    ClassSite,
		URL:      "https://gitlab.com",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "cloudflare",
		Class:    ClassSite,
		URL:      "https://www.cloudflare.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "aws",
		Class:    ClassSite,
		URL:      "https://aws.amazon.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "google-cloud",
		Class:    ClassSite,
		URL:      "https://cloud.google.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "digitalocean",
		Class:    ClassSite,
		URL:      "https://www.digitalocean.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "docker-hub",
		Class:    ClassSite,
		URL:      "https://hub.docker.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "npm-registry",
		Class:    ClassSite,
		URL:      "https://registry.npmjs.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "pypi",
		Class:    ClassSite,
		URL:      "https://pypi.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "rubygems",
		Class:    ClassSite,
		URL:      "https://rubygems.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "python-org",
		Class:    ClassSite,
		URL:      "https://www.python.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "go-dev",
		Class:    ClassSite,
		URL:      "https://go.dev",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "kernel-org",
		Class:    ClassSite,
		URL:      "https://www.kernel.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "mdn",
		Class:    ClassSite,
		URL:      "https://developer.mozilla.org",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},
	{
		// Re-pointed for the same reason as netflix: staged 302-with-no-body,
		// measured here as 200 with 4.9 MB.
		Name:     "cnn",
		Class:    ClassSite,
		URL:      "https://www.cnn.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "bbc",
		Class:    ClassSite,
		URL:      "https://www.bbc.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "new-york-times",
		Class:    ClassSite,
		URL:      "https://www.nytimes.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "the-guardian",
		Class:    ClassSite,
		URL:      "https://www.theguardian.com",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "ap-news",
		Class:    ClassSite,
		URL:      "https://apnews.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "al-jazeera",
		Class:    ClassSite,
		URL:      "https://www.aljazeera.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "deutsche-welle",
		Class:    ClassSite,
		URL:      "https://www.dw.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "france-24",
		Class:    ClassSite,
		URL:      "https://www.france24.com",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},
	{
		// The favicon, not the front page: the front page is 120 KB and Wikimedia's
		// ATS does not honor Range (measured: 200, whole asset), so it is the one
		// destination that would routinely exceed the WIRE budget even though the
		// read cap bounds what is kept.
		Name:     "wikipedia",
		Class:    ClassSite,
		URL:      "https://www.wikipedia.org/static/favicon/wikipedia.ico",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "wordpress",
		Class:    ClassSite,
		URL:      "https://wordpress.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "imdb",
		Class:    ClassSite,
		URL:      "https://www.imdb.com",
		Expect:   ExpectStatus,
		Status:   202,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "internet-archive",
		Class:    ClassSite,
		URL:      "https://archive.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "noaa-weather",
		Class:    ClassSite,
		URL:      "https://www.weather.gov",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "qq",
		Class:    ClassSite,
		URL:      "https://www.qq.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "sina",
		Class:    ClassSite,
		URL:      "https://www.sina.com.cn",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "taobao",
		Class:    ClassSite,
		URL:      "https://www.taobao.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "jd-com",
		Class:    ClassSite,
		URL:      "https://www.jd.com",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "mail-ru",
		Class:    ClassSite,
		URL:      "https://mail.ru",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "vk",
		Class:    ClassSite,
		URL:      "https://vk.com",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "naver",
		Class:    ClassSite,
		URL:      "https://www.naver.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "line",
		Class:    ClassSite,
		URL:      "https://line.me",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},
	{
		// Re-pointed: measured here as 301 with no body, while the staged run had
		// it answering with one. Unstable in the same way, caught from the other
		// direction (it is absent from the zero-body list).
		Name:     "times-of-india",
		Class:    ClassSite,
		URL:      "https://timesofindia.indiatimes.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "globo",
		Class:    ClassSite,
		URL:      "https://www.globo.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "mercadolibre",
		Class:    ClassSite,
		URL:      "https://www.mercadolibre.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "abc-australia",
		Class:    ClassSite,
		URL:      "https://www.abc.net.au",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "news24",
		Class:    ClassSite,
		URL:      "https://www.news24.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "zoom",
		Class:    ClassSite,
		URL:      "https://zoom.us",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "slack",
		Class:    ClassSite,
		URL:      "https://slack.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "dropbox",
		Class:    ClassSite,
		URL:      "https://www.dropbox.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "notion",
		Class:    ClassSite,
		URL:      "https://www.notion.so",
		Expect:   ExpectStatus,
		Status:   307,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "trello",
		Class:    ClassSite,
		URL:      "https://trello.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "atlassian",
		Class:    ClassSite,
		URL:      "https://www.atlassian.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "figma",
		Class:    ClassSite,
		URL:      "https://www.figma.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "steam",
		Class:    ClassSite,
		URL:      "https://store.steampowered.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "playstation",
		Class:    ClassSite,
		URL:      "https://www.playstation.com",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "xbox",
		Class:    ClassSite,
		URL:      "https://www.xbox.com",
		Expect:   ExpectStatus,
		Status:   307,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "nintendo",
		Class:    ClassSite,
		URL:      "https://www.nintendo.com",
		Expect:   ExpectStatus,
		Status:   301,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "roblox",
		Class:    ClassSite,
		URL:      "https://www.roblox.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "riot-games",
		Class:    ClassSite,
		URL:      "https://www.riotgames.com",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},

	// Reputation. NOT PART OF THE HEALTH SCORE -- see ClassReputation. Six of
	// these eight refused this datacenter exit outright (403, except reuters at
	// 401) and on a residential or cellular exit are expected to return clean. A
	// provider that passes them is more useful to a real user; a provider that
	// fails them is a hosted exit, not a broken one.
	//
	// The remaining two are kept because they keep the class honest about what it
	// measures, and both carry a note: reddit is the endpoint that produced the
	// three contradictory readings quoted on ClassReputation, and stackoverflow
	// never refused anything -- it redirects.
	{
		Name:     "akamai",
		Class:    ClassReputation,
		URL:      "https://www.akamai.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// The staged runs recorded ecosia as NOT refusing; this host measured 403
		// with 4472 bytes on the same day the table was built. Left where the
		// owner classified it -- a vendor whose answer differs run to run is
		// exactly what an unscored diagnostic class is for.
		Name:     "ecosia",
		Class:    ClassReputation,
		URL:      "https://www.ecosia.org",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "reddit",
		Class:    ClassReputation,
		URL:      "https://www.reddit.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "etsy",
		Class:    ClassReputation,
		URL:      "https://www.etsy.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// 302 with an empty body, four staged runs and one here. Recorded because
		// it constrains how this class is read: stackoverflow is marked reputation
		// but did NOT refuse this datacenter exit -- it redirects everyone. Before
		// this entry declared its status it failed every run, which reads in a log
		// exactly like an ip-reputation refusal and is not one. Do not interpret a
		// stack-overflow failure as reputation without checking the status first.
		Name:     "stack-overflow",
		Class:    ClassReputation,
		URL:      "https://stackoverflow.com",
		Expect:   ExpectStatus,
		Status:   302,
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "reuters",
		Class:    ClassReputation,
		URL:      "https://www.reuters.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "canva",
		Class:    ClassReputation,
		URL:      "https://www.canva.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "epic-games",
		Class:    ClassReputation,
		URL:      "https://www.epicgames.com",
		Headers:  map[string]string{"Range": rangeFirst1KiB},
		MaxBytes: maxAssetBytes,
	},
}

// verifyDNSJSON proves a DoH response actually resolved the name, which a
// status code cannot: a captive portal, a transparent proxy or an interception
// box all answer 200 with a body. Only an answer section proves resolution.
//
// It decodes ONLY the Answer field, on purpose. The seven operators disagree
// about the rest of the document -- dns.alidns.com returns Question as an
// OBJECT where every other operator returns an array, so a struct that declared
// Question would fail to unmarshal AliDNS's perfectly good answer and score a
// working resolver as a captive portal.
//
// Status is not required to be 0 either. dns.adguard-dns.com omits the field
// entirely, and Go would leave it at 0 -- which happens to equal NOERROR, so a
// check on it would be passing by accident rather than by evidence. A non-empty
// answer with non-empty data is the evidence.
func verifyDNSJSON(body []byte) error {
	var doc struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("the response is not dns json (%w); a 200 with a body is not proof a name was resolved", err)
	}
	if len(doc.Answer) == 0 {
		return errors.New("the dns response carries no answer section; the request was answered by something that did not resolve the name")
	}
	for _, a := range doc.Answer {
		if strings.TrimSpace(a.Data) != "" {
			return nil
		}
	}
	return errors.New("every record in the dns answer section is empty")
}

// verifyIPText proves an echo endpoint returned an address rather than a
// portal's html. TrimSpace first: checkip.amazonaws.com terminates with a
// newline.
func verifyIPText(body []byte) error {
	text := strings.TrimSpace(string(body))
	if net.ParseIP(text) == nil {
		return fmt.Errorf("%q is not an ip address; this endpoint returns one, so something else answered", truncate(text, 64))
	}
	return nil
}

// verifyContains proves a fixed-text endpoint returned its fixed text.
//
// Substring, after TrimSpace, NOT equality: detectportal.firefox.com serves
// "success\n" -- eight bytes for a seven-character word -- so an equality check
// would fail for every provider forever, which is noise dressed as signal.
//
// Every want below is measured to appear within the first maxConnectivityBytes
// of its endpoint's body, which is what makes a substring test on a CAPPED read
// meaningful: cloudflare's trace document puts ip= in its first 40 bytes, and
// example.com's title in its first 60.
func verifyContains(want string) func([]byte) error {
	return func(body []byte) error {
		text := strings.TrimSpace(string(body))
		if !strings.Contains(text, want) {
			return fmt.Errorf("the body does not contain %q (got %q); a captive portal answers 200 with a page", want, truncate(text, 64))
		}
		return nil
	}
}

// truncate keeps an unexpected body from filling the log with someone's login
// page.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// CheckResult is one destination's outcome. It is recorded for failures as
// fully as for successes -- especially ByteCount, which is what separates "the
// destination refused us with a page of explanation" (bytes flowed; the tunnel
// works, the content provider said no) from "nothing came back at all" (the
// blackhole signature). Losing that distinction would defeat the point of
// grouping by class.
type CheckResult struct {
	Name                     string
	Class                    Class
	OK                       bool
	StatusCode               int   // 0 when the request never produced a response
	ByteCount                int64 // bytes of body actually read, capped; set on failures too
	Latency                  time.Duration
	Err                      string // "" when OK
	TLSAuthenticationFailure bool   // the peer's certificate could not authenticate the requested host
}

// ClassSummary is the ok/total tally for one class.
type ClassSummary struct {
	OK    int
	Total int
}

// Result is one full run.
type Result struct {
	Checks []CheckResult
	// TLSAuthenticationFailure is true when any sampled HTTPS peer failed
	// certificate-chain or hostname verification. It is intentionally separate
	// from the score: one forged identity is a hard integrity failure and must
	// not be diluted by unrelated successful destinations.
	TLSAuthenticationFailure bool
	// OKCount and Total cover the SCORED classes only, and only the
	// destinations this run SAMPLED. A datacenter provider that fails every
	// reputation destination still reads as fully healthy here, which is the
	// intended behaviour -- see ClassReputation.
	OKCount int
	Total   int
	// ByClass is the per-class tally for the scored classes only, over the
	// sample.
	ByClass map[Class]ClassSummary
	// Reputation is the tally for ClassReputation, reported ALONGSIDE the score
	// and never inside it, so a log line can carry reputation=2/4 without that
	// figure contaminating ok=N/M.
	Reputation ClassSummary
	// TableTotal is the size of the full table the sample was drawn from, all
	// classes included, and is rendered as table=N so nobody reads "dns=4/4" as
	// "the table holds four resolvers". Zero when the run was not sampled (a
	// test driving check() directly), and then omitted from Summary.
	TableTotal int
}

// Options tunes a single Check call. The zero value is valid and uses the
// defaults below.
type Options struct {
	// PerRequestTimeout bounds each individual request. Zero or negative uses
	// DefaultPerRequestTimeout.
	PerRequestTimeout time.Duration
	// Budget bounds the whole run, so a provider that swallows every request
	// cannot hold the pass open for Concurrency-batched multiples of the
	// per-request timeout. Zero or negative uses DefaultBudget.
	Budget time.Duration
	// Concurrency caps simultaneous requests. Zero or negative uses
	// DefaultConcurrency.
	Concurrency int
	// Rand draws this run's sample. Nil -- which is what production passes --
	// means a fresh generator seeded from crypto/rand for every run, which is
	// the whole anti-gaming property: the provider cannot know what it will be
	// asked for. Tests set it to make a run reproducible.
	//
	// It must not be SHARED between concurrent runs: math/rand.Rand is stateful
	// and not goroutine-safe, and the prober probes several providers at once.
	// Leaving it nil is what makes that safe, so production leaves it nil.
	Rand *rand.Rand

	// AllDestinations runs EVERY destination in the table instead of drawing a
	// sample. It exists for operator-run diagnostics -- "show me the complete
	// picture for this fleet right now" -- and is deliberately not the default.
	//
	// Two things change when it is set, and the caller owns both:
	//
	//   1. Cost. The sample is bounded by construction; the full table is not.
	//      At the current table it is ~4.5x the bytes and ~4.5x the requests.
	//   2. The anti-gaming property is LOST. A fixed, fully-enumerable
	//      destination list is exactly what a provider can whitelist. Random
	//      sampling is what makes that impractical, so scheduled production
	//      passes must keep sampling; this is for on-demand inspection.
	//
	// Concurrency must be raised to AllConcurrency to match, and the
	// per-request timeout sized against RoundsForAllDestinations, or the run
	// is cut off mid-table and destinations fail for a reason that has
	// nothing to do with the provider. Note the direction cmd/egress-prober
	// takes: it holds the whole-run Budget at one -probe-timeout and lowers
	// the per-request timeout, rather than growing the budget -- growing it
	// is how the health check came to cost 2.8x its stated budget.
	AllDestinations bool
}

// Defaults for Options. They are vars so tests can lower them.
//
// The three are one piece of arithmetic, not three independent knobs:
//
//	rounds = ceil(SamplePerRun()/DefaultConcurrency) = ceil(30/6) = 5
//	rounds * DefaultPerRequestTimeout = 5 * 10s = 50s <= DefaultBudget
//
// Changing any one of them -- or raising a sample size -- without the others
// either cuts off the last round (destinations fail for a reason the provider
// had nothing to do with) or lets a swallowing provider stall the pass for
// longer than one probe timeout. cmd/egress-prober derives the same ratio from
// -probe-timeout, and TestEgressHealthAddsAtMostOneProbeTimeout holds it.
var (
	// DefaultPerRequestTimeout is generous because every probe runs over a COLD
	// tunnel: nothing is warm, keep-alives are disabled, and each request pays
	// an in-tunnel DoH resolution plus a full TLS handshake. Treat it as a floor
	// rather than a preference -- it is what forced DefaultConcurrency up when
	// the table grew.
	DefaultPerRequestTimeout = 10 * time.Second
	// DefaultBudget bounds a whole run: rounds * DefaultPerRequestTimeout, so a
	// run that is going to be a total loss ends rather than stalling the pass,
	// and a healthy one is never cut off mid-round.
	DefaultBudget = 60 * time.Second
	// DefaultConcurrency was 3 while the table held 9 destinations. It is 6
	// because the per-request timeout is a floor: at 3, a 60s probe budget
	// spread over ceil(30/3) = 10 rounds leaves 6s per request, which is BELOW
	// the cold-tunnel figure above, and cold-start timeouts would then be
	// charged to providers as blackholes.
	//
	// Note that this is sized against the SAMPLE, not the table: sampling is
	// what keeps a 140-destination table costing 30 requests. The constraint it
	// trades against is about handshakes rather than bytes -- simultaneous TLS
	// handshakes over one cold gvisor tunnel with keep-alives disabled contend
	// with each other and inflate every latency.
	//
	// The field signal that this is set too high is specific: first-round
	// timeouts spread evenly across ALL classes, on providers whose geolocation
	// succeeded. That means lower it (and lengthen -probe-timeout to keep the
	// arithmetic above), not that the providers are bad.
	DefaultConcurrency = 6
)

// ErrNilClient is returned when client is nil. Checks run in spawned
// goroutines, where a nil-client panic could not be recovered by the caller, so
// it is rejected up front. Mirrors geolocate.ErrNilClient.
var ErrNilClient = errors.New("egresshealth: client must not be nil")

// ErrNoDestinations is returned when the destination table is empty, which
// would make a run vacuous: 0/0 checks passed is not evidence of anything.
var ErrNoDestinations = errors.New("egresshealth: at least one destination is required")

// ErrNoBudget is returned when the context is already done on entry. This is a
// STRUCTURAL failure and must not be reported as a run, because a run started
// on a dead context returns 0/N -- identical to a total blackhole. The caller
// (see prober) is expected to check for it and log "skipped" rather than a
// verdict.
var ErrNoBudget = errors.New("egresshealth: the context was already done before any check ran")

// ErrUnsupported reports that the server does not implement the egress-health
// ingest endpoint (it answers 404). It lives here rather than in ingest for the
// same reason bandwidth.ErrUnsupported lives in bandwidth: the prober
// classifies the outcome, and it must be able to tell "this deployment has not
// shipped the endpoint yet" from a real submission failure without importing
// the submitter implementation its interfaces exist to keep out.
//
// It is a clean SKIP, not a failure. A prober pointed at an older server keeps
// probing and keeps logging health; it simply records none.
var ErrUnsupported = errors.New("egresshealth: the server does not implement the provider egress health endpoint")

// Check runs a random sample of the production destinations through client and
// returns the full pattern of what worked.
//
// The sample is drawn per call and per class (see sampleDestinations and
// sampleSizes): the same provider probed twice is asked for different
// destinations, and no provider can know in advance which ones. Coverage of
// the table accumulates across runs and across the fleet rather than being
// paid on every run.
//
// One destination failing never aborts the run: the pattern of failures IS the
// value, so every sampled destination is attempted and every outcome recorded.
// An error is returned only when something structural stopped the run from
// happening at all (see ErrNilClient, ErrNoDestinations, ErrNoBudget) -- so
// `err == nil && OKCount == 0` is a real, trustworthy total-blackhole reading,
// distinguishable from a run that never took place.
//
// In production client egresses through one provider's tunnel, so what this
// measures is that provider's willingness and ability to carry ordinary
// traffic.
func Check(ctx context.Context, client *http.Client, opts Options) (*Result, error) {
	var chosen []Destination
	if opts.AllDestinations {
		chosen = append([]Destination(nil), destinations...)
	} else {
		chosen = sampleDestinations(destinations, sampleSizes, opts.rng())
	}
	res, err := check(ctx, client, chosen, opts)
	if res != nil {
		res.TableTotal = len(destinations)
	}
	return res, err
}

// SamplePerRun is how many requests one run makes: the sum of the per-class
// sample sizes, bounded by what the table actually holds.
//
// It is exported because cmd/egress-prober sizes a SAMPLED run's per-request
// deadline from it -- rounds = ceil(SamplePerRun()/DefaultConcurrency). A
// full-table run uses RoundsForAllDestinations instead, and because that
// divides one probe timeout across many more rounds, the prober refuses to
// start when the result falls below DefaultPerRequestTimeout rather than
// charging honest providers with cold-start timeouts.
// AllConcurrency is the concurrency an AllDestinations run uses. It is raised
// above DefaultConcurrency because otherwise the round count -- and with it
// the wall clock -- grows linearly with the table. It is not raised further:
// every request rides the SAME provider tunnel, so concurrency here is load on
// the provider under test, and a diagnostic that overloads its subject
// measures the overload.
const AllConcurrency = 10

// RoundsForAllDestinations is how many sequential rounds a full-table run
// takes at AllConcurrency. A caller sizing a per-request timeout to fit a
// fixed budget needs this number, not the sampled round count: dividing a
// budget by the sampled rounds and then spending it over these rounds is how
// the shipped -egress-health-all default came to draw 2.8x its stated
// budget.
func RoundsForAllDestinations() int {
	return (len(destinations) + AllConcurrency - 1) / AllConcurrency
}

func SamplePerRun() int {
	n := 0
	for _, c := range tableClasses(destinations) {
		n += sampleCount(destinations, c, sampleSizes)
	}
	return n
}

func (o Options) perRequestTimeout() time.Duration {
	if 0 < o.PerRequestTimeout {
		return o.PerRequestTimeout
	}
	return DefaultPerRequestTimeout
}

func (o Options) budget() time.Duration {
	if 0 < o.Budget {
		return o.Budget
	}
	return DefaultBudget
}

func (o Options) concurrency() int {
	if 0 < o.Concurrency {
		return o.Concurrency
	}
	return DefaultConcurrency
}

// rng is the randomness one run's sample is drawn from.
//
// A caller-supplied generator is used as given, which is what makes a test
// reproducible. Otherwise a fresh one is built per run and seeded from
// crypto/rand -- not from the clock, and never from the global generator. The
// anti-gaming property is that a provider cannot predict which destinations it
// will be asked for, and a clock seed is predictable to anyone who knows
// roughly when the pass started. The global generator is avoided for a duller
// reason: it is shared process-wide state that any other package can reseed.
func (o Options) rng() *rand.Rand {
	if o.Rand != nil {
		return o.Rand
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice. If it ever does, a clock seed
		// still samples: a weaker unpredictability is worth having, a skipped
		// run is not.
		return rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(b[:]))))
}

// maxBytes is the body read cap for this destination: its own, clamped to the
// package ceiling so no single entry can raise the documented budget.
func (d Destination) maxBytes() int64 {
	if 0 < d.MaxBytes && d.MaxBytes < MaxBodyBytes {
		return int64(d.MaxBytes)
	}
	return MaxBodyBytes
}

// tableClasses lists the classes present in dests, in TABLE order and without
// repeats.
//
// Table order, never map iteration order, and that is load-bearing rather than
// tidy: sampleDestinations draws from the generator once per class, so a class
// order that varied between runs would make the same seed produce a different
// sample. Reproducibility is what the tests turn on.
func tableClasses(dests []Destination) []Class {
	seen := map[Class]bool{}
	var out []Class
	for _, d := range dests {
		if seen[d.Class] {
			continue
		}
		seen[d.Class] = true
		out = append(out, d.Class)
	}
	return out
}

// sampleCount is how many destinations of class c a run draws: the declared
// size, or the whole class when it is smaller than that or has no declared size
// at all. See sampleSizes for why "no declared size" means "probe it all".
func sampleCount(dests []Destination, c Class, sizes map[Class]int) int {
	total := 0
	for _, d := range dests {
		if d.Class == c {
			total++
		}
	}
	n, declared := sizes[c]
	if !declared || n <= 0 || total < n {
		return total
	}
	return n
}

// sampleDestinations draws each class's sample for one run.
//
// It is a partial Fisher-Yates over each class's indices, so every subset of a
// class is equally likely and no destination is drawn twice. The result is
// returned in TABLE order (the indices are sorted afterwards) so that Checks,
// FailedNames and the log line keep reading in the order the table declares,
// whatever the draw was -- a summary that reordered itself per run would be
// undiffable.
//
// It takes the table, the sizes and the generator as arguments rather than
// reaching for package state, which is the same seam check() uses: a test can
// drive it with a stub table and a fixed seed and assert exactly what came out.
func sampleDestinations(dests []Destination, sizes map[Class]int, r *rand.Rand) []Destination {
	byClass := map[Class][]int{}
	for i, d := range dests {
		byClass[d.Class] = append(byClass[d.Class], i)
	}

	var picked []int
	for _, c := range tableClasses(dests) {
		idx := byClass[c]
		n := sampleCount(dests, c, sizes)
		if n >= len(idx) {
			picked = append(picked, idx...)
			continue
		}
		shuffled := append([]int(nil), idx...)
		for i := 0; i < n; i++ {
			j := i + r.Intn(len(shuffled)-i)
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		picked = append(picked, shuffled[:n]...)
	}
	sort.Ints(picked)

	out := make([]Destination, 0, len(picked))
	for _, i := range picked {
		out = append(out, dests[i])
	}
	return out
}

// check is the seam Check is built on, taking the destination table explicitly
// so tests can drive httptest servers instead of the real internet. Same shape
// as geolocate's locate().
func check(ctx context.Context, client *http.Client, dests []Destination, opts Options) (*Result, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if len(dests) == 0 {
		return nil, ErrNoDestinations
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoBudget, err)
	}

	ctx, cancel := context.WithTimeout(ctx, opts.budget())
	defer cancel()

	perRequest := opts.perRequestTimeout()
	results := make([]CheckResult, len(dests))
	sem := make(chan struct{}, opts.concurrency())
	var wg sync.WaitGroup
	for i := range dests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = fetch(ctx, client, dests[i], perRequest)
		}(i)
	}
	wg.Wait()

	// ByClass and Reputation are seeded from the SAMPLE, not from the results
	// that happened to come back, so a class in which every single check failed
	// still appears as 0/n. Accumulating only from successes would make the
	// datacenter-IP case -- the whole reason the class dimension exists --
	// vanish from the map at exactly the moment it matters.
	byClass := map[Class]ClassSummary{}
	var reputation ClassSummary
	total := 0
	for _, d := range dests {
		if !scored(d.Class) {
			reputation.Total++
			continue
		}
		total++
		s := byClass[d.Class]
		s.Total++
		byClass[d.Class] = s
	}

	okCount := 0
	tlsAuthenticationFailure := false
	for _, r := range results {
		if r.TLSAuthenticationFailure {
			tlsAuthenticationFailure = true
		}
		if !r.OK {
			continue
		}
		// An unscored class contributes to its own tally and to NOTHING else.
		// Folding it into okCount would make every hosted provider read as
		// degraded; see ClassReputation.
		if !scored(r.Class) {
			reputation.OK++
			continue
		}
		okCount++
		s := byClass[r.Class]
		s.OK++
		byClass[r.Class] = s
	}

	return &Result{
		Checks:                   results,
		TLSAuthenticationFailure: tlsAuthenticationFailure,
		OKCount:                  okCount,
		Total:                    total,
		ByClass:                  byClass,
		Reputation:               reputation,
	}, nil
}

// fetch performs one destination's check. It never returns an error: a failed
// destination is a RESULT, and the run keeps going.
func fetch(ctx context.Context, client *http.Client, d Destination, timeout time.Duration) CheckResult {
	r := CheckResult{Name: d.Name, Class: d.Class}
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}
	// Set first, so a destination's own Headers can still override it.
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		r.TLSAuthenticationFailure = isTLSAuthenticationFailure(err)
		return r
	}
	defer resp.Body.Close()
	r.StatusCode = resp.StatusCode

	// The body is read even on an error status, and ByteCount is recorded
	// either way: a 403 with a page of explanation proves the tunnel carried
	// bytes in both directions and the CONTENT PROVIDER refused, which is a
	// different fault from nothing coming back at all.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, d.maxBytes()))
	r.ByteCount = int64(len(body))
	r.Latency = time.Since(start)

	if readErr != nil {
		r.Err = readErr.Error()
		return r
	}
	if err := d.judge(resp.StatusCode, body); err != nil {
		r.Err = err.Error()
		return r
	}
	r.OK = true
	return r
}

// isTLSAuthenticationFailure identifies certificate-chain and hostname
// verification failures without parsing their human-readable text. These are
// qualitatively different from timeouts, refused connections, HTTP statuses,
// and content mismatches: a provider returned a TLS identity that does not
// authenticate the destination the client requested.
//
// CertificateVerificationError is the normal crypto/tls wrapper. The x509
// fallbacks cover transports with a custom VerifyPeerCertificate callback,
// including the provider tunnel's pinning path, which can return the underlying
// verification error directly.
func isTLSAuthenticationFailure(err error) bool {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		return true
	}
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}
	var certificateInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certificateInvalidErr) {
		return true
	}
	var hostnameErr x509.HostnameError
	return errors.As(err, &hostnameErr)
}

// judge applies the destination's success contract to what came back. It is
// separated from the transport so the rule can be read -- and reasoned about --
// without an http server in the way.
func (d Destination) judge(status int, body []byte) error {
	switch d.Expect {
	case ExpectStatus:
		if d.Status <= 0 {
			// A misconfigured entry must fail loudly rather than accept anything:
			// "expect exactly nothing in particular" is how ExpectStatus would
			// become a hole in the blackhole rule.
			return fmt.Errorf("destination declares ExpectStatus with no Status; it cannot be judged")
		}
		if status != d.Status {
			// Exact, not "any 2xx". A provider that synthesizes a bare 200 must
			// not pass a destination that is supposed to answer 204.
			return fmt.Errorf("status %d, want exactly %d", status, d.Status)
		}
	case ExpectReachable:
		// Any 2xx or 3xx: the host answered through the provider. A 4xx/5xx is
		// still a refusal and still fails, and a blackholing provider produces
		// no response at all, so this remains a real liveness check.
		if status < 200 || 400 <= status {
			return fmt.Errorf("status %d, want any 2xx or 3xx", status)
		}
	default: // ExpectBody
		if status < 200 || 300 <= status {
			// 3xx counts as a failure, not a redirect to follow. The production
			// client refuses redirects outright (providertunnel's CheckRedirect),
			// so a 3xx here is a destination that did not serve what was asked
			// for. A destination that legitimately answers 3xx should declare
			// ExpectStatus rather than be chased.
			return fmt.Errorf("status %d", status)
		}
		if len(body) == 0 {
			// THE blackhole signature, and the reason this rule is spelled out: a
			// status line with no body is exactly what a provider that terminates
			// the connection itself, or one whose upstream returns a stub,
			// produces. Counting it as success would let the failure this package
			// exists to catch pass the check. This stays the DEFAULT contract; an
			// endpoint where an empty body is correct must say so with
			// ExpectStatus.
			return fmt.Errorf("status %d with an empty body", status)
		}
	}
	if d.Verify == nil {
		return nil
	}
	if err := d.Verify(body); err != nil {
		return fmt.Errorf("status %d but the body did not verify: %w", status, err)
	}
	return nil
}

// DestinationHosts returns the host of every production destination,
// de-duplicated and in table order.
//
// This mirrors geolocate.SourceHosts and exists for the same reason: nothing
// outside this package should keep a second copy of the endpoint list. The
// prober's container cannot resolve DNS, so the operator passes explicit
// addresses to the confinement self-check with -confinement-address, and this
// is how they obtain the host list to translate. A hand-maintained copy would
// drift on the first table change while the check kept reporting success.
//
// It covers the WHOLE table, not a sample: any destination can be drawn on any
// run, so the confinement check has to prove every one of them unreachable
// directly, and the tunnel client has to be allowed to reach every one of them.
// This list is therefore now ~140 hosts rather than ~30 -- see the README on
// what that means for an operator maintaining -confinement-address by hand.
//
// Reputation hosts are included: they are reached through the tunnel like any
// other destination, so the confinement check must prove them unreachable
// directly. Being excluded from the SCORE has nothing to do with confinement.
//
// A URL that does not parse, or carries no host, is skipped rather than
// panicking -- but destinations is a compile-time constant table and
// TestDestinationHostsCoversEveryDestination fails if any entry goes missing.
func DestinationHosts() []string {
	seen := map[string]bool{}
	hosts := make([]string, 0, len(destinations))
	for _, d := range destinations {
		u, err := url.Parse(d.URL)
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

// Destinations returns a copy of the production table -- all of it, not one
// run's sample.
//
// A copy, not the table: a caller that mutated it -- or the Headers map inside
// an entry -- would silently change what every subsequent probe measures, and
// the drift would be invisible in the table's own source. Callers that only
// need the host list want DestinationHosts; callers sizing a run's budget want
// SamplePerRun.
func Destinations() []Destination {
	out := make([]Destination, len(destinations))
	for i, d := range destinations {
		out[i] = d
		if d.Headers != nil {
			headers := make(map[string]string, len(d.Headers))
			for k, v := range d.Headers {
				headers[k] = v
			}
			out[i].Headers = headers
		}
	}
	return out
}

// Summary renders the one-line, per-pass form:
//
//	ok=25/26 dns=4/4 connectivity=5/5 cdn=4/5 site=12/12 reputation=1/4 table=140
//
// Every figure except table= is over the destinations this run SAMPLED, which
// is why the table size is on the line: dns=4/4 is four of seven asked and
// answered, not a four-entry class.
//
// The reputation figure sits OUTSIDE ok=N/M on purpose and is never added into
// it: it measures how the exit's address-and-client pair is treated by
// bot-management vendors, not whether the provider works. See ClassReputation.
//
// Class order is Classes, never map iteration order, so successive passes are
// diffable. Classes absent from the sample are omitted; a class present in the
// sample but absent from Classes is appended in sorted order rather than
// silently dropped.
func (r *Result) Summary() string {
	if r == nil {
		return "ok=0/0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ok=%d/%d", r.OKCount, r.Total)
	for _, c := range r.orderedClasses() {
		s := r.ByClass[c]
		fmt.Fprintf(&b, " %s=%d/%d", c, s.OK, s.Total)
	}
	if 0 < r.Reputation.Total {
		fmt.Fprintf(&b, " %s=%d/%d", ClassReputation, r.Reputation.OK, r.Reputation.Total)
	}
	if 0 < r.TableTotal {
		fmt.Fprintf(&b, " table=%d", r.TableTotal)
	}
	if r.TLSAuthenticationFailure {
		b.WriteString(" tls_authentication_failure=true")
	}
	return b.String()
}

// orderedClasses lists the classes present in ByClass: the declared ones first,
// in Classes order, then any others sorted, so a class added to the table but
// not to Classes still shows up.
func (r *Result) orderedClasses() []Class {
	out := make([]Class, 0, len(r.ByClass))
	declared := map[Class]bool{}
	for _, c := range Classes {
		declared[c] = true
		if _, ok := r.ByClass[c]; ok {
			out = append(out, c)
		}
	}
	var extra []string
	for c := range r.ByClass {
		if !declared[c] {
			extra = append(extra, string(c))
		}
	}
	sort.Strings(extra)
	for _, c := range extra {
		out = append(out, Class(c))
	}
	return out
}

// FailedNames lists the SCORED destinations that did not pass, in table order.
// The summary line says how many failed; this says which, which is what turns a
// log line into something actionable -- and with a sampled table it is the only
// way to know WHICH destinations a run actually asked for.
//
// Reputation failures are not here, because they are not failures of the thing
// ok=N/M reports; ReputationFailedNames lists those separately so a log line
// can keep the two apart.
func (r *Result) FailedNames() []string {
	if r == nil {
		return nil
	}
	var names []string
	for _, c := range r.Checks {
		if !c.OK && scored(c.Class) {
			names = append(names, c.Name)
		}
	}
	return names
}

// ReputationFailedNames lists the reputation destinations that refused this
// exit, in table order. Which vendor refused is the whole content of the
// signal -- "akamai,etsy" and "reuters" say different things about what the
// exit looks like from outside.
func (r *Result) ReputationFailedNames() []string {
	if r == nil {
		return nil
	}
	var names []string
	for _, c := range r.Checks {
		if !c.OK && !scored(c.Class) {
			names = append(names, c.Name)
		}
	}
	return names
}
