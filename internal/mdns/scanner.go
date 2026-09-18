package mdns

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsPort       = 5353
	maxCIDRHosts   = 1 << 16
	maxConcurrency = 1024
	questionChunk  = 20
)

var multicastAddress = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}

type Config struct {
	CIDR        string
	Ports       PortSet
	Timeout     time.Duration
	Concurrency int
	Verbose     bool
	LogWriter   io.Writer
}

type Scanner struct {
	config  Config
	network *net.IPNet
	hosts   []net.IP
	logger  *log.Logger
}

func NewScanner(config Config) (*Scanner, error) {
	if len(config.Ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	if config.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}
	if config.Concurrency <= 0 || config.Concurrency > maxConcurrency {
		return nil, fmt.Errorf("concurrency must be between 1 and %d", maxConcurrency)
	}

	network, hosts, err := IPv4Hosts(config.CIDR)
	if err != nil {
		return nil, err
	}
	writer := config.LogWriter
	if writer == nil || !config.Verbose {
		writer = io.Discard
	}
	return &Scanner{
		config:  config,
		network: network,
		hosts:   hosts,
		logger:  log.New(writer, "mdns: ", log.LstdFlags),
	}, nil
}

// IPv4Hosts validates and expands a CIDR with a hard upper bound.
func IPv4Hosts(value string) (*net.IPNet, []net.IP, error) {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid IPv4 CIDR %q: %w", value, err)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, nil, fmt.Errorf("CIDR %q is not IPv4", value)
	}
	network.IP = network.IP.To4()
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, nil, fmt.Errorf("CIDR %q is not IPv4", value)
	}
	total := uint64(1) << uint(32-ones)
	if total > maxCIDRHosts {
		return nil, nil, fmt.Errorf("CIDR %q contains %d addresses; maximum is %d (/16)", value, total, maxCIDRHosts)
	}

	hosts := make([]net.IP, 0, total)
	start := network.IP.Mask(network.Mask)
	for offset := uint64(0); offset < total; offset++ {
		if total > 2 && (offset == 0 || offset == total-1) {
			continue
		}
		value := uint64(start[0])<<24 | uint64(start[1])<<16 | uint64(start[2])<<8 | uint64(start[3])
		value += offset
		hosts = append(hosts, net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)))
	}
	return network, hosts, nil
}

// Discover performs four bounded DNS-SD phases within one overall timeout.
func (s *Scanner) Discover(parent context.Context) ([]Asset, error) {
	ctx, cancel := context.WithTimeout(parent, s.config.Timeout)
	defer cancel()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open UDP socket: %w", err)
	}
	defer conn.Close()

	aggregator := NewAggregator()
	responders := make(map[string]net.IP)

	enumeration := buildPackets([]question{{name: serviceEnumerationName, qtype: dns.TypePTR}})
	sources, err := s.runPhase(ctx, conn, enumeration, s.hosts, aggregator, 4)
	if err != nil {
		return nil, err
	}
	mergeSources(responders, sources)

	serviceTypes := aggregator.ServiceTypes()
	if len(serviceTypes) == 0 {
		return []Asset{}, nil
	}
	s.logger.Printf("discovered %d service types", len(serviceTypes))

	typeQuestions := make([]question, 0, len(serviceTypes))
	for _, serviceType := range serviceTypes {
		typeQuestions = append(typeQuestions, question{name: serviceType, qtype: dns.TypePTR})
	}
	sources, err = s.runPhase(ctx, conn, buildPackets(typeQuestions), sourceValues(responders), aggregator, 3)
	if err != nil {
		return nil, err
	}
	mergeSources(responders, sources)

	instances := aggregator.Instances()
	detailQuestions := make([]question, 0, len(instances)*2)
	for _, instance := range instances {
		detailQuestions = append(detailQuestions,
			question{name: instance, qtype: dns.TypeSRV},
			question{name: instance, qtype: dns.TypeTXT},
		)
	}
	sources, err = s.runPhase(ctx, conn, buildPackets(detailQuestions), sourceValues(responders), aggregator, 2)
	if err != nil {
		return nil, err
	}
	mergeSources(responders, sources)

	targets := aggregator.Targets()
	addressQuestions := make([]question, 0, len(targets)*2)
	for _, target := range targets {
		addressQuestions = append(addressQuestions,
			question{name: target, qtype: dns.TypeA},
			question{name: target, qtype: dns.TypeAAAA},
		)
	}
	if len(addressQuestions) != 0 {
		if _, err := s.runPhase(ctx, conn, buildPackets(addressQuestions), sourceValues(responders), aggregator, 1); err != nil {
			return nil, err
		}
	}

	return aggregator.Assets(s.config.Ports, s.network), nil
}

type question struct {
	name  string
	qtype uint16
}

func buildPackets(questions []question) [][]byte {
	packets := make([][]byte, 0, (len(questions)+questionChunk-1)/questionChunk)
	for start := 0; start < len(questions); start += questionChunk {
		end := start + questionChunk
		if end > len(questions) {
			end = len(questions)
		}
		msg := new(dns.Msg)
		msg.MsgHdr.Id = 0
		msg.RecursionDesired = false
		for _, value := range questions[start:end] {
			msg.Question = append(msg.Question, dns.Question{
				Name:   dns.Fqdn(value.name),
				Qtype:  value.qtype,
				Qclass: dns.ClassINET | 1<<15,
			})
		}
		packet, err := msg.Pack()
		if err == nil {
			packets = append(packets, packet)
		}
	}
	return packets
}

type response struct {
	packet []byte
	source net.IP
}

func (s *Scanner) runPhase(parent context.Context, conn *net.UDPConn, packets [][]byte, targets []net.IP, aggregator *Aggregator, phasesLeft int) ([]net.IP, error) {
	if len(packets) == 0 {
		return nil, nil
	}
	deadline, ok := parent.Deadline()
	if !ok {
		return nil, fmt.Errorf("scan context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	budget := remaining / time.Duration(phasesLeft)
	phaseCtx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	phaseDeadline, _ := phaseCtx.Deadline()
	if err := conn.SetReadDeadline(phaseDeadline); err != nil {
		return nil, fmt.Errorf("set UDP read deadline: %w", err)
	}
	if err := conn.SetWriteDeadline(phaseDeadline); err != nil {
		return nil, fmt.Errorf("set UDP write deadline: %w", err)
	}

	responses := make(chan response, 256)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buffer := make([]byte, 65535)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			select {
			case responses <- response{packet: packet, source: source.IP}:
			case <-phaseCtx.Done():
				return
			}
		}
	}()

	destinations := make([]net.IP, 0, len(targets)+1)
	destinations = append(destinations, multicastAddress.IP)
	destinations = append(destinations, targets...)
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		s.sendPackets(phaseCtx, conn, packets, destinations)
	}()

	sources := make(map[string]net.IP)
	for {
		select {
		case item := <-responses:
			s.consumeResponse(item, aggregator, sources)
		case <-readDone:
			cancel()
			<-sendDone
			for {
				select {
				case item := <-responses:
					s.consumeResponse(item, aggregator, sources)
				default:
					return sourceValues(sources), nil
				}
			}
		case <-parent.Done():
			cancel()
			if err := conn.SetReadDeadline(time.Now()); err != nil {
				s.logger.Printf("wake UDP reader: %v", err)
			}
			<-readDone
			<-sendDone
			if parent.Err() == context.DeadlineExceeded {
				return sourceValues(sources), nil
			}
			return nil, parent.Err()
		}
	}
}
func (s *Scanner) consumeResponse(item response, aggregator *Aggregator, sources map[string]net.IP) {
	if err := aggregator.AddPacket(item.packet, item.source); err != nil {
		s.logger.Printf("ignored malformed packet from %s: %v", item.source, err)
		return
	}
	sources[item.source.String()] = append(net.IP(nil), item.source...)
}

type sendJob struct {
	packet      []byte
	destination net.IP
}

func (s *Scanner) sendPackets(ctx context.Context, conn *net.UDPConn, packets [][]byte, destinations []net.IP) {
	workers := s.config.Concurrency
	jobsCount := len(packets) * len(destinations)
	if workers > jobsCount {
		workers = jobsCount
	}
	jobs := make(chan sendJob)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				address := &net.UDPAddr{IP: job.destination, Port: mdnsPort}
				if _, err := conn.WriteToUDP(job.packet, address); err != nil && ctx.Err() == nil {
					s.logger.Printf("query %s: %v", address, err)
				}
			}
		}()
	}

sendLoop:
	for _, destination := range destinations {
		for _, packet := range packets {
			select {
			case jobs <- sendJob{packet: packet, destination: destination}:
			case <-ctx.Done():
				break sendLoop
			}
		}
	}
	close(jobs)
	wg.Wait()
}

func mergeSources(destination map[string]net.IP, sources []net.IP) {
	for _, source := range sources {
		destination[source.String()] = source
	}
}

func sourceValues(values map[string]net.IP) []net.IP {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]net.IP, 0, len(keys))
	for _, key := range keys {
		result = append(result, values[key])
	}
	return result
}
