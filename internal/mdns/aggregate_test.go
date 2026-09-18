package mdns

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAggregatorJoinsDNSServiceRecords(t *testing.T) {
	msg := fixtureMessage(t)
	msg.Compress = true
	packet, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	aggregator := NewAggregator()
	if err := aggregator.AddPacket(packet, net.ParseIP("192.168.1.10")); err != nil {
		t.Fatalf("AddPacket() error = %v", err)
	}
	if err := aggregator.AddPacket(packet, net.ParseIP("192.168.1.10")); err != nil {
		t.Fatalf("duplicate AddPacket() error = %v", err)
	}

	serviceTypes := aggregator.ServiceTypes()
	for _, expected := range []string{
		"_workstation._tcp.local.",
		"_http._tcp.local.",
		"_smb._tcp.local.",
		"_qdiscover._tcp.local.",
		"_device-info._tcp.local.",
		"_afpovertcp._tcp.local.",
	} {
		if !contains(serviceTypes, expected) {
			t.Errorf("service types %v do not include %s", serviceTypes, expected)
		}
	}

	ports, err := ParsePorts("80,86")
	if err != nil {
		t.Fatal(err)
	}
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	assets := aggregator.Assets(ports, network)
	if len(assets) != 2 {
		t.Fatalf("got %d assets; want 2: %+v", len(assets), assets)
	}

	var qdiscover Asset
	for _, asset := range assets {
		if asset.Service == "_qdiscover._tcp.local." {
			qdiscover = asset
		}
	}
	if qdiscover.Port != 86 {
		t.Fatalf("qdiscover port = %d; want 86", qdiscover.Port)
	}
	if qdiscover.Hostname != "nas.local." {
		t.Errorf("hostname = %q; want nas.local.", qdiscover.Hostname)
	}
	if qdiscover.TTL != 120 {
		t.Errorf("TTL = %d; want 120", qdiscover.TTL)
	}
	if qdiscover.IP != "192.168.1.10" {
		t.Errorf("IP = %q; want 192.168.1.10", qdiscover.IP)
	}
	if !reflect.DeepEqual(qdiscover.RawBanner, []string{
		"accessPort=86",
		"accessType=https",
		"displayModel=TS-464C",
		"flagOnly",
		"fwBuildNum=20260214",
		"fwVer=5.2.9",
		"model=TS-X64",
	}) {
		t.Errorf("raw banner = %#v", qdiscover.RawBanner)
	}
	if qdiscover.StructuredBanner["displayModel"] != "TS-464C" || qdiscover.StructuredBanner["flagOnly"] != "" {
		t.Errorf("structured banner = %#v", qdiscover.StructuredBanner)
	}
	if !strings.Contains(qdiscover.Banner, "accessType=https") || !strings.Contains(qdiscover.Banner, "fwBuildNum=20260214") {
		t.Errorf("banner lost TXT data: %q", qdiscover.Banner)
	}

	var httpAsset Asset
	for _, asset := range assets {
		if asset.Service == "_http._tcp.local." {
			httpAsset = asset
		}
	}
	if httpAsset.StructuredBanner["path"] != "/" {
		t.Errorf("HTTP path = %q; want /", httpAsset.StructuredBanner["path"])
	}
	_, outsideNetwork, _ := net.ParseCIDR("198.51.100.0/24")
	if outside := aggregator.Assets(ports, outsideNetwork); len(outside) != 0 {
		t.Errorf("CIDR filter returned out-of-range assets: %+v", outside)
	}
}

func TestAggregatorRejectsMalformedPacket(t *testing.T) {
	aggregator := NewAggregator()
	if err := aggregator.AddPacket([]byte{0xff, 0x01}, nil); err == nil {
		t.Fatal("expected malformed packet error")
	}
}

func TestWriteTextIsStableAndComplete(t *testing.T) {
	aggregator := NewAggregator()
	aggregator.AddMessage(fixtureMessage(t), net.ParseIP("192.168.1.10"))
	ports, _ := ParsePorts("86")
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	var output strings.Builder
	if err := WriteText(&output, aggregator.Assets(ports, network)); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	text := output.String()
	for _, expected := range []string{
		"services:",
		"answers:",
		"service: _qdiscover._tcp.local.",
		"accessType=https",
		"accessPort=86",
		"model=TS-X64",
		"displayModel=TS-464C",
		"fwVer=5.2.9",
		"fwBuildNum=20260214",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("output does not contain %q:\n%s", expected, text)
		}
	}
}

func fixtureMessage(t *testing.T) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.Response = true
	services := []struct {
		service  string
		instance string
		port     uint16
	}{
		{"_workstation._tcp.local.", "NAS._workstation._tcp.local.", 9},
		{"_http._tcp.local.", "NAS._http._tcp.local.", 80},
		{"_smb._tcp.local.", "NAS._smb._tcp.local.", 445},
		{"_qdiscover._tcp.local.", "NAS._qdiscover._tcp.local.", 86},
		{"_device-info._tcp.local.", "NAS._device-info._tcp.local.", 9},
		{"_afpovertcp._tcp.local.", "NAS._afpovertcp._tcp.local.", 548},
	}

	for _, item := range services {
		msg.Answer = append(msg.Answer,
			&dns.PTR{Hdr: rrHeader(serviceEnumerationName, dns.TypePTR, 4500), Ptr: item.service},
			&dns.PTR{Hdr: rrHeader(item.service, dns.TypePTR, 4500), Ptr: item.instance},
		)
		msg.Extra = append(msg.Extra, &dns.SRV{
			Hdr: rrHeader(item.instance, dns.TypeSRV, 120), Port: item.port, Target: "nas.local.",
		})
	}
	msg.Extra = append(msg.Extra,
		&dns.AAAA{Hdr: rrHeader("nas.local.", dns.TypeAAAA, 120), AAAA: net.ParseIP("fe80::1234")},
		&dns.TXT{Hdr: rrHeader("NAS._http._tcp.local.", dns.TypeTXT, 4500), Txt: []string{"path=/"}},
		&dns.A{Hdr: rrHeader("nas.local.", dns.TypeA, 120), A: net.ParseIP("192.168.1.10")},
		&dns.TXT{Hdr: rrHeader("NAS._qdiscover._tcp.local.", dns.TypeTXT, 4500), Txt: []string{
			"model=TS-X64",
			"accessType=https",
			"fwBuildNum=20260214",
			"displayModel=TS-464C",
			"accessPort=86",
			"fwVer=5.2.9",
			"flagOnly",
		}},
	)
	return msg
}

func rrHeader(name string, rrType uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrType, Class: dns.ClassINET, Ttl: ttl}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
