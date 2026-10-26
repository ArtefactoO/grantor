package netguard

import (
	"net"
	"strings"
)

const PrivateKubernetesDNSV1 = "private-kubernetes-dns.v1"

// IsKubernetesDNSHost accepts a service or pod FQDN in the standard cluster
// domain, never a suffix lookalike, wildcard, search-domain name or URL.
func IsKubernetesDNSHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if (len(parts) != 5 && len(parts) != 6) || len(host) > 253 ||
		strings.Join(parts[len(parts)-3:], ".") != "svc.cluster.local" {
		return false
	}
	for _, label := range parts[:len(parts)-3] {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// KubernetesDNSNetworkGuard is derived only from an approved execution and
// transport target. Private literals retain their existing approval contract.
func KubernetesDNSNetworkGuard(mode, tlsMode string, endpoints []string) string {
	if mode != "connector" || (tlsMode != "" && tlsMode != "disabled") || len(endpoints) == 0 {
		return ""
	}
	for _, endpoint := range endpoints {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil && !strings.Contains(endpoint, ":") {
			host, err = endpoint, nil
		}
		if err != nil || !IsKubernetesDNSHost(host) {
			return ""
		}
	}
	return PrivateKubernetesDNSV1
}
