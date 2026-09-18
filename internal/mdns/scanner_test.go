package mdns

import "testing"

func TestIPv4Hosts(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantHosts int
		wantErr   bool
	}{
		{name: "slash 32", cidr: "192.0.2.9/32", wantHosts: 1},
		{name: "slash 31", cidr: "192.0.2.8/31", wantHosts: 2},
		{name: "slash 30 omits network and broadcast", cidr: "192.0.2.8/30", wantHosts: 2},
		{name: "maximum slash 16", cidr: "10.20.0.0/16", wantHosts: 65534},
		{name: "too large", cidr: "10.0.0.0/15", wantErr: true},
		{name: "IPv6", cidr: "2001:db8::/64", wantErr: true},
		{name: "invalid", cidr: "not-a-cidr", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, hosts, err := IPv4Hosts(tt.cidr)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("IPv4Hosts() error = %v", err)
			}
			if len(hosts) != tt.wantHosts {
				t.Errorf("got %d hosts; want %d", len(hosts), tt.wantHosts)
			}
		})
	}
}

func TestNewScannerValidation(t *testing.T) {
	ports, _ := ParsePorts("80")
	if _, err := NewScanner(Config{CIDR: "192.0.2.0/24", Ports: ports, Timeout: 1, Concurrency: 1025}); err == nil {
		t.Fatal("expected concurrency limit error")
	}
}
