package mdns

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const serviceEnumerationName = "_services._dns-sd._udp.local."

type srvRecord struct {
	target string
	port   uint16
}

type txtValue struct {
	key   string
	value string
}

// Aggregator joins PTR, SRV, TXT, A, and AAAA records regardless of RR order.
type Aggregator struct {
	serviceTypes  map[string]string
	instances     map[string]string
	srv           map[string]map[string]srvRecord
	txt           map[string]map[string]struct{}
	addresses     map[string]map[string]Address
	structuredTXT map[string]map[string]txtValue
	ttl           map[string]uint32
	sources       map[string]map[string]struct{}
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		serviceTypes:  make(map[string]string),
		instances:     make(map[string]string),
		srv:           make(map[string]map[string]srvRecord),
		txt:           make(map[string]map[string]struct{}),
		addresses:     make(map[string]map[string]Address),
		structuredTXT: make(map[string]map[string]txtValue),
		ttl:           make(map[string]uint32),
		sources:       make(map[string]map[string]struct{}),
	}
}

// AddPacket safely parses and aggregates one DNS message.
func (a *Aggregator) AddPacket(packet []byte, source net.IP) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		return fmt.Errorf("unpack DNS packet: %w", err)
	}
	a.AddMessage(&msg, source)
	return nil
}

// AddMessage aggregates all answer, authority, and additional records.
func (a *Aggregator) AddMessage(msg *dns.Msg, source net.IP) {
	records := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	records = append(records, msg.Answer...)
	records = append(records, msg.Ns...)
	records = append(records, msg.Extra...)

	messageInstances := make(map[string]struct{})
	for _, rr := range records {
		header := rr.Header()
		owner := canonical(header.Name)
		a.rememberTTL(owner, header.Ttl)
		if header.Ttl == 0 {
			a.removeRecord(rr)
			continue
		}

		switch record := rr.(type) {
		case *dns.PTR:
			target := canonical(record.Ptr)
			if owner == canonical(serviceEnumerationName) {
				a.serviceTypes[target] = dns.Fqdn(record.Ptr)
				continue
			}
			if strings.HasSuffix(owner, ".local.") && strings.HasPrefix(owner, "_") {
				a.serviceTypes[owner] = dns.Fqdn(header.Name)
				a.instances[target] = dns.Fqdn(header.Name)
				messageInstances[target] = struct{}{}
			}
		case *dns.SRV:
			target := canonical(record.Target)
			if a.srv[owner] == nil {
				a.srv[owner] = make(map[string]srvRecord)
			}
			key := fmt.Sprintf("%s:%d", target, record.Port)
			a.srv[owner][key] = srvRecord{target: dns.Fqdn(record.Target), port: record.Port}
			messageInstances[owner] = struct{}{}
		case *dns.TXT:
			if a.txt[owner] == nil {
				a.txt[owner] = make(map[string]struct{})
			}
			if a.structuredTXT[owner] == nil {
				a.structuredTXT[owner] = make(map[string]txtValue)
			}
			for _, value := range record.Txt {
				a.txt[owner][value] = struct{}{}
				key, item, _ := strings.Cut(value, "=")
				canonicalKey := strings.ToLower(key)
				if _, exists := a.structuredTXT[owner][canonicalKey]; !exists {
					a.structuredTXT[owner][canonicalKey] = txtValue{key: key, value: item}
				}
			}
			messageInstances[owner] = struct{}{}
		case *dns.A:
			a.addAddress(owner, record.A.String(), "IPv4")
		case *dns.AAAA:
			a.addAddress(owner, record.AAAA.String(), "IPv6")
		}
	}

	if source == nil {
		return
	}
	for instance := range messageInstances {
		if a.sources[instance] == nil {
			a.sources[instance] = make(map[string]struct{})
		}
		a.sources[instance][source.String()] = struct{}{}
	}
}

func (a *Aggregator) removeRecord(rr dns.RR) {
	owner := canonical(rr.Header().Name)
	switch record := rr.(type) {
	case *dns.PTR:
		target := canonical(record.Ptr)
		if owner == canonical(serviceEnumerationName) {
			delete(a.serviceTypes, target)
			return
		}
		delete(a.instances, target)
		delete(a.sources, target)
	case *dns.SRV:
		key := fmt.Sprintf("%s:%d", canonical(record.Target), record.Port)
		delete(a.srv[owner], key)
	case *dns.TXT:
		delete(a.txt, owner)
		delete(a.structuredTXT, owner)
	case *dns.A:
		delete(a.addresses[owner], "IPv4:"+record.A.String())
	case *dns.AAAA:
		delete(a.addresses[owner], "IPv6:"+record.AAAA.String())
	}
}

func (a *Aggregator) addAddress(hostname, ip, family string) {
	if a.addresses[hostname] == nil {
		a.addresses[hostname] = make(map[string]Address)
	}
	a.addresses[hostname][family+":"+ip] = Address{IP: ip, Family: family}
}

func (a *Aggregator) rememberTTL(name string, ttl uint32) {
	if ttl == 0 {
		return
	}
	if current := a.ttl[name]; current == 0 || ttl < current {
		a.ttl[name] = ttl
	}
}

func (a *Aggregator) ServiceTypes() []string {
	values := make([]string, 0, len(a.serviceTypes))
	for _, value := range a.serviceTypes {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (a *Aggregator) Instances() []string {
	values := make([]string, 0, len(a.instances))
	for instance := range a.instances {
		values = append(values, instance)
	}
	sort.Strings(values)
	return values
}

func (a *Aggregator) Targets() []string {
	seen := make(map[string]string)
	for _, records := range a.srv {
		for _, record := range records {
			seen[canonical(record.target)] = record.target
		}
	}
	values := make([]string, 0, len(seen))
	for _, value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

// Assets returns stable, de-duplicated assets whose SRV port and IPv4 CIDR match.
func (a *Aggregator) Assets(ports PortSet, network *net.IPNet) []Asset {
	assets := make([]Asset, 0)
	seen := make(map[string]struct{})

	for instanceKey, records := range a.srv {
		service, ok := a.instances[instanceKey]
		if !ok {
			continue
		}
		for _, record := range records {
			if !ports.Contains(record.port) {
				continue
			}

			addresses := a.assetAddresses(instanceKey, canonical(record.target), network)
			if len(addresses) == 0 {
				continue
			}
			key := strings.Join([]string{canonical(service), instanceKey, canonical(record.target), fmt.Sprint(record.port)}, "|")
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}

			raw := sortedKeys(a.txt[instanceKey])
			structured := make(map[string]string, len(a.structuredTXT[instanceKey]))
			for _, value := range a.structuredTXT[instanceKey] {
				structured[value.key] = value.value
			}

			assets = append(assets, Asset{
				IP:               addresses[0].IP,
				Port:             record.port,
				Hostname:         record.target,
				Service:          service,
				Instance:         dns.Fqdn(instanceKey),
				TTL:              minNonZero(a.ttl[canonical(service)], a.ttl[instanceKey], a.ttl[canonical(record.target)]),
				Addresses:        addresses,
				TXT:              append([]string(nil), raw...),
				RawBanner:        append([]string(nil), raw...),
				StructuredBanner: structured,
				Banner:           strings.Join(raw, ","),
			})
		}
	}

	sort.Slice(assets, func(i, j int) bool {
		left := fmt.Sprintf("%s|%s|%s|%05d", assets[i].Service, assets[i].Instance, assets[i].Hostname, assets[i].Port)
		right := fmt.Sprintf("%s|%s|%s|%05d", assets[j].Service, assets[j].Instance, assets[j].Hostname, assets[j].Port)
		return left < right
	})
	return assets
}

func (a *Aggregator) assetAddresses(instance, target string, network *net.IPNet) []Address {
	values := make(map[string]Address)
	matchedCIDR := network == nil
	hasExplicitIPv4 := false
	for key, address := range a.addresses[target] {
		if address.Family == "IPv4" {
			hasExplicitIPv4 = true
			ip := net.ParseIP(address.IP)
			if network != nil && !network.Contains(ip) {
				continue
			}
			matchedCIDR = true
		}
		values[key] = address
	}
	if !hasExplicitIPv4 {
		for source := range a.sources[instance] {
			ip := net.ParseIP(source)
			if ip != nil && ip.To4() != nil && (network == nil || network.Contains(ip)) {
				values["IPv4:"+source] = Address{IP: source, Family: "IPv4"}
				matchedCIDR = true
			}
		}
	}
	if !matchedCIDR {
		return nil
	}
	addresses := make([]Address, 0, len(values))
	for _, address := range values {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].Family != addresses[j].Family {
			return addresses[i].Family < addresses[j].Family
		}
		return addresses[i].IP < addresses[j].IP
	})
	return addresses
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func minNonZero(values ...uint32) uint32 {
	var minimum uint32
	for _, value := range values {
		if value != 0 && (minimum == 0 || value < minimum) {
			minimum = value
		}
	}
	return minimum
}

func canonical(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}
