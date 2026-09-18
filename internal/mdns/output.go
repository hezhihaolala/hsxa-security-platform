package mdns

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

func WriteJSON(w io.Writer, assets []Asset) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(assets); err != nil {
		return fmt.Errorf("encode JSON output: %w", err)
	}
	return nil
}

func WriteText(w io.Writer, assets []Asset) error {
	if _, err := fmt.Fprintln(w, "services:"); err != nil {
		return err
	}
	for _, asset := range assets {
		if _, err := fmt.Fprintf(w, "- service: %s\n  instance: %s\n  answers:\n", asset.Service, asset.Instance); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "    ip: %s\n    port: %d\n    hostname: %s\n    ttl: %d\n", asset.IP, asset.Port, asset.Hostname, asset.TTL); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "    addresses:"); err != nil {
			return err
		}
		for _, address := range asset.Addresses {
			if _, err := fmt.Fprintf(w, "      - %s: %s\n", address.Family, address.IP); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "    raw_banner: %q\n    banner: %s\n", asset.RawBanner, asset.Banner); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "    structured_banner:"); err != nil {
			return err
		}
		keys := make([]string, 0, len(asset.StructuredBanner))
		for key := range asset.StructuredBanner {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := asset.StructuredBanner[key]
			if strings.ContainsAny(value, ":#{}[]\n") || strings.TrimSpace(value) != value {
				value = fmt.Sprintf("%q", value)
			}
			if _, err := fmt.Fprintf(w, "      %s: %s\n", key, value); err != nil {
				return err
			}
		}
	}
	return nil
}
