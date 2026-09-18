package mdns

// Address is an IP address associated with a DNS-SD service target.
type Address struct {
	IP     string `json:"ip"`
	Family string `json:"family"`
}

// Asset is one aggregated DNS-SD service instance.
type Asset struct {
	IP               string            `json:"ip"`
	Port             uint16            `json:"port"`
	Hostname         string            `json:"hostname"`
	Service          string            `json:"service"`
	Instance         string            `json:"instance"`
	TTL              uint32            `json:"ttl"`
	Addresses        []Address         `json:"addresses"`
	TXT              []string          `json:"txt"`
	RawBanner        []string          `json:"raw_banner"`
	StructuredBanner map[string]string `json:"structured_banner"`
	Banner           string            `json:"banner"`
}
