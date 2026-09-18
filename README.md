# mDNS Asset Scanner

`mdns-asset-scanner` is a small Go CLI for authorized asset discovery with
mDNS and DNS-SD. It enumerates advertised service types, resolves their
instances, and joins PTR, SRV, TXT, A, and AAAA records into stable asset
records.

It performs discovery only. It does not exploit vulnerabilities, bypass
authentication, or modify remote systems.

## Build and test

Go 1.24 or newer is recommended.

```bash
go mod download
go test ./...
go vet ./...
go build -o bin/mdns-asset-scanner ./cmd/mdns-asset-scanner
```

On Windows, the output file may be named `bin/mdns-asset-scanner.exe`.

## Usage

Only scan networks that you own or are explicitly authorized to assess.

```bash
go run ./cmd/mdns-asset-scanner \
  --cidr 192.168.1.0/24 \
  --ports 80,443,445,5000-5010 \
  --timeout 3s \
  --concurrency 64
```

JSON output:

```bash
go run ./cmd/mdns-asset-scanner \
  --cidr 192.168.1.0/24 \
  --ports 80,86,443,445,548 \
  --timeout 3s \
  --concurrency 64 \
  --json
```

Diagnostic logging can be enabled with `--verbose`.

| Flag | Default | Description |
| --- | --- | --- |
| `--cidr` | required | Authorized IPv4 CIDR to probe. |
| `--ports` | `1-65535` | SRV ports to include; accepts single ports, commas, and inclusive ranges. |
| `--timeout` | `3s` | Overall discovery deadline. |
| `--concurrency` | `64` | UDP send workers; valid range is 1-1024. |
| `--json` | `false` | Emit structured JSON instead of text. |
| `--verbose` | `false` | Write packet and parsing diagnostics to stderr. |

CIDRs larger than `/16` are rejected to prevent accidental unbounded scans.
For prefixes up to `/30`, the network and broadcast addresses are omitted.

## Discovery flow

1. Query `_services._dns-sd._udp.local` for service-type PTR records.
2. Query every returned service type for service-instance PTR records.
3. Query every instance for SRV and TXT records.
4. Query every SRV target for A and AAAA records.
5. Join records by service type, instance, target, and port; filter by CIDR and
   the requested SRV ports; then sort and de-duplicate the output.

The scanner sends a standard multicast query to `224.0.0.251:5353`. It also
sends mDNS queries directly to addresses in the authorized IPv4 CIDR through a
bounded worker pool. Queries request unicast replies so the scanner can use an
ephemeral local UDP port without taking exclusive ownership of port 5353.

Unknown and vendor-specific service types are retained. TXT strings are kept
verbatim in `raw_banner`/`txt`; a stable, sorted `banner` and parsed
`structured_banner` are also emitted. Flag-style TXT values without `=` are
represented with an empty structured value.

Example text shape:

```text
services:
- service: _qdiscover._tcp.local.
  instance: NAS._qdiscover._tcp.local.
  answers:
    ip: 192.168.1.10
    port: 86
    hostname: nas.local.
    ttl: 120
    addresses:
      - IPv4: 192.168.1.10
      - IPv6: fe80::1234
    raw_banner: ["accessPort=86" "accessType=https" "displayModel=TS-464C" "fwBuildNum=20260214" "fwVer=5.2.9" "model=TS-X64"]
    banner: accessPort=86,accessType=https,displayModel=TS-464C,fwBuildNum=20260214,fwVer=5.2.9,model=TS-X64
    structured_banner:
      accessPort: 86
      accessType: https
      displayModel: TS-464C
      fwBuildNum: 20260214
      fwVer: 5.2.9
      model: TS-X64
```

## Protocol boundary

mDNS is normally limited to the local layer-2 link. Routers generally do not
forward multicast traffic, so discovery across routed subnets depends on the
network design, multicast relays/reflectors, host firewalls, and whether target
devices accept direct mDNS queries. An empty result therefore does not prove
that a host is absent. The CIDR active-probe mode improves coverage where
direct UDP/5353 is permitted, but it cannot bypass those protocol and network
boundaries.

The test suite uses synthetic DNS packets that contain PTR, SRV, TXT, A, and
AAAA records for common and vendor-specific service types. It does not require
a real mDNS device and does not alter production scan behavior.
