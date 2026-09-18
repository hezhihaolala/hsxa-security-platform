package mdns

import (
	"io"
	"log"
	"net"
	"testing"

	"github.com/miekg/dns"
)

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
func TestConsumeResponseRejectsSourceOutsideCIDR(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	scanner := &Scanner{network: network, logger: log.New(io.Discard, "", 0)}
	aggregator := NewAggregator()
	sources := make(map[string]net.IP)
	packet, err := fixtureMessage(t).Pack()
	if err != nil {
		t.Fatal(err)
	}

	scanner.consumeResponse(response{packet: packet, source: net.ParseIP("192.168.2.10")}, aggregator, sources)
	if len(sources) != 0 || len(aggregator.ServiceTypes()) != 0 {
		t.Fatalf("outside response was promoted: sources=%v types=%v", sources, aggregator.ServiceTypes())
	}

	scanner.consumeResponse(response{packet: packet, source: net.ParseIP("192.168.1.10")}, aggregator, sources)
	if len(sources) != 1 || len(aggregator.ServiceTypes()) == 0 {
		t.Fatalf("inside response was not promoted: sources=%v types=%v", sources, aggregator.ServiceTypes())
	}
}

func TestBuildPacketsChunksQuestionsAndRequestsUnicastReply(t *testing.T) {
	questions := make([]question, 21)
	for i := range questions {
		questions[i] = question{name: "_service._tcp.local.", qtype: dns.TypePTR}
	}
	packets := buildPackets(questions)
	if len(packets) != 2 {
		t.Fatalf("got %d packets; want 2", len(packets))
	}
	count := 0
	for _, packet := range packets {
		var msg dns.Msg
		if err := msg.Unpack(packet); err != nil {
			t.Fatalf("Unpack() error = %v", err)
		}
		count += len(msg.Question)
		for _, q := range msg.Question {
			if q.Qclass&(1<<15) == 0 {
				t.Errorf("question does not request unicast reply: %#v", q)
			}
		}
	}
	if count != len(questions) {
		t.Errorf("packed %d questions; want %d", count, len(questions))
	}
}
