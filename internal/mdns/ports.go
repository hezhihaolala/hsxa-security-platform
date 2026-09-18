package mdns

import (
	"fmt"
	"strconv"
	"strings"
)

// PortSet is the set of SRV ports accepted by a scan.
type PortSet map[uint16]struct{}

// ParsePorts parses comma-separated ports and inclusive ranges.
func ParsePorts(value string) (PortSet, error) {
	ports := make(PortSet)
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("ports must not be empty")
	}

	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("invalid empty port item")
		}

		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid port range %q", item)
		}

		start, err := parsePort(parts[0])
		if err != nil {
			return nil, err
		}
		end := start
		if len(parts) == 2 {
			end, err = parsePort(parts[1])
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("invalid descending port range %q", item)
			}
		}

		for port := int(start); port <= int(end); port++ {
			ports[uint16(port)] = struct{}{}
		}
	}

	return ports, nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q: expected 1-65535", value)
	}
	return uint16(n), nil
}

func (p PortSet) Contains(port uint16) bool {
	_, ok := p[port]
	return ok
}
