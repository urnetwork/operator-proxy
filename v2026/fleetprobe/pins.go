// This file validates the certificate-pin snapshot shared by one fleet pass.
package fleetprobe

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/urnetwork/operator-proxy/v2026/geolocate"
	"github.com/urnetwork/operator-proxy/v2026/ingest"
)

// ValidateGeolocationPins converts the server response into the tunnel's pin
// map. Every source must have both pins and extra served hosts cannot widen the
// allowlist.
func ValidateGeolocationPins(servedPins map[string]ingest.GeolocationPin) (map[string][]string, error) {
	sourceHosts := geolocate.SourceHosts()
	if len(sourceHosts) == 0 {
		return nil, fmt.Errorf("no geolocation source hosts to pin")
	}

	pins := make(map[string][]string, len(sourceHosts))
	missingHosts := []string{}
	for _, sourceHost := range sourceHosts {
		pin, ok := servedPins[sourceHost]
		if !ok || pin.Leaf == "" || pin.Intermediate == "" {
			missingHosts = append(missingHosts, sourceHost)
			continue
		}
		pins[sourceHost] = []string{pin.Leaf, pin.Intermediate}
	}
	if 0 < len(missingHosts) {
		servedHosts := make([]string, 0, len(servedPins))
		for host := range servedPins {
			servedHosts = append(servedHosts, host)
		}
		sort.Strings(servedHosts)
		return nil, fmt.Errorf(
			"the server served no usable certificate pin for geolocation source host(s) %s (it served %d host(s): %s). "+
				"The prober will not probe an unpinned geolocation source: the lookup rides the tunnel of the provider being measured, so unpinned means that provider can forge its own location. "+
				"Either the server's observation job has not run for that host, or geolocate/sources.go and the server's host list have drifted apart",
			strings.Join(missingHosts, " "), len(servedPins), strings.Join(servedHosts, " "))
	}

	extraCount := 0
	for host := range servedPins {
		if _, wanted := pins[host]; !wanted {
			extraCount++
		}
	}
	if 0 < extraCount {
		log.Printf("egress-prober: ignoring %d server pin(s) that are not geolocation sources; the pin map is also the tunnel allowlist and must not be widened by the response", extraCount)
	}
	return pins, nil
}
