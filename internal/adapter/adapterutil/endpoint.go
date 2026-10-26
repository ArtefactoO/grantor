package adapterutil

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SplitEndpoint разбирает endpoint вида host[:port]; при отсутствии порта
// используется defaultPort (per-engine значение передаётся вызывающим).
func SplitEndpoint(endpoint string, defaultPort uint16) (host string, port uint16, err error) {
	if endpoint == "" {
		return "", 0, errors.New("empty endpoint")
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && strings.Contains(addrErr.Err, "missing port") {
			return endpoint, defaultPort, nil
		}
		return "", 0, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	parsed, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || parsed == 0 {
		return "", 0, fmt.Errorf("invalid port in endpoint %q", endpoint)
	}
	return host, uint16(parsed), nil
}
