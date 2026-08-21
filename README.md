# UniversalScanner (Rust)

Rust port of the C# [UniversalScanner](https://github.com/julienblitte/UniversalScanner) — a
multi-brand network device discovery tool for IP cameras, access-control systems, and UPS units.
The original is a ~8,300-line C#/.NET 4.5 WinForms app; here it is re-implemented as a library
crate (`universal-scanner`) plus a CLI (`uscan`). No UI.

[中文文档](README_zh.md)

## What it does

`uscan` sends UDP discovery probes over multicast, broadcast, and per-interface sockets, then
prints each device that answers: protocol, version, IP, MAC, model, and serial. There is one
engine per vendor protocol, 28 in total:

- 26 are 1:1 ports of the C# engines — probe bytes, ports, parsing, and fallback behavior included.
- 2 are new in this port: **ARP/GARP** (L2 capture via libpcap) and **TVT** (MHED multicast
  protocol, reverse-engineered from a live device capture).
- An **mDNS broker** (port 5353) parses DNS-wire responses once and serves the three mDNS
  engines (Axis, Google Cast, Arecont) instead of each running its own listener.

Behavioral parity with the C# original is the acceptance bar, and it is verified offline: 32
captured request/response fixtures (`.selftest`) are replayed through the same parsing path that
live scanning uses. `uscan selftest` runs all of them; all green means the parsing layer still
matches the C# behavior.

## Requirements

- Rust ≥ 1.75 (edition 2021)
- Linux: `libpcap-dev` and `pkg-config` (the `pcap` crate links the system libpcap); macOS
  ships libpcap

## Build

```bash
cargo build --release
```

The binary lands at `target/release/uscan`.

## Usage

Omitting the subcommand runs a scan:

```bash
uscan
```

Sample output (CSV; `table` is the default format):

```
$ uscan scan --timeout 5 --format csv
protocol,version,ip,mac,type,serial
"SSDP","0","192.168.1.111","","Private Upnp SDK","device_3_0-0067120380000304"
"Hikvision","1","192.168.1.101","","DS-2CD3T25-I3","DS-2CD3T25-I320200730AACHE40182"
"Dahua","1","192.168.1.111","BC:32:5F:71:9B:03","IP Camera","0067120380000304"
```

More examples:

```bash
uscan scan --protocols ssdp,hikvision --format csv
uscan scan --protocols dahua --format json --show-version
uscan scan --format tsv --rescan 30 --timeout 120   # rescan every 30s, exit after 120s
```

### Commands

| Command | What it does |
|---|---|
| `uscan [scan]` | Discovery run (default) |
| `uscan selftest [engine]` | Offline fixture replay, all or one engine (case-insensitive) |
| `uscan selftest2pcap IN OUT [--dest-port N]` | Wrap a fixture as a single UDP loopback pcap packet; refuses to overwrite an existing OUT |
| `uscan list-protocols` | Engine table: ID, name, port, listen mode |
| `uscan update-oui` | Download the IEEE OUI database to `~/.cache/uscan/oui.txt` |
| `uscan tvt-set --mac M --ip I [flags]` | Set a static IP on a TVT camera (L2 set-IP multicast, MHED type 3) |

`tvt-set` transmits the packet 3 times at 100 ms intervals. Useful flags: `--dhcp` (put the
camera back on DHCP; ip/mask/gateway are ignored), `--dry-run` (print the packet hex with the
password field zeroed, send nothing), `--password` (admin password, ≤ 21 bytes, base64 in the
packet), `--interface` (pick the outgoing interface IP). The protocol was reverse-engineered
from a live capture (cf. `tvt-iptool-linux`); after a set-IP, verify with
`uscan scan --protocols TVT` — the same serial should reappear under the new IP.

### Scan flags

| Flag | Meaning |
|---|---|
| `--protocols a,b,c` | Engine filter, case-insensitive (default: all) |
| `--format table\|csv\|json\|tsv` | Output format; `json` is JSON Lines |
| `--batch` | Buffer and print everything in discovery order at exit |
| `--rescan SECS` / `--timeout SECS` | Rescan interval / graceful-exit deadline |
| `--show-version` | Show the Version column |
| `--pcap-out PATH` | Dump probes and responses to a pcap file |
| `--config PATH` | TOML config file (see below) |
| `--arp` / `--no-arp` | Toggle the ARP/GARP engine (off by default) |
| `--no-color` | Disable colored output |

The 10 config switches below also exist as CLI flags (`--enable-ipv6`, `--no-debug`,
`--dahua-net-scan`, …); CLI always wins.

### Output

Rows stream out as devices are found; `--batch` buffers them and prints in discovery order when
the scan ends (timeout or Ctrl-C).

CSV/TSV always carry the header `protocol,version,ip,mac,type,serial`. Quoting follows the C#
`exportAsCSV` rules (every field quoted, embedded quotes doubled), so files line up with the
original tool's exports. The `mac` column is new in the Rust port and sits right after `ip`;
engines whose replies carry no MAC (SSDP, WSDiscovery, Hikvision, …) leave it empty.

### Configuration

Resolution order: CLI flags > TOML file > built-in defaults.

File lookup: `--config PATH` > `$UNIVERSAL_SCANNER_CONFIG` >
`$XDG_CONFIG_HOME/universal-scanner/config.toml` > `~/.config/universal-scanner/config.toml`.
A missing file is skipped silently; unknown keys are an error (the key name is printed).

```toml
enable_ipv4              = true   # IPv4 discovery
enable_ipv6              = false  # IPv6 discovery
force_link_local         = true   # keep link-local (fe80::) devices
force_zeroconf           = false  # keep zeroconf (169.254/16) devices
force_generic_protocols  = false  # dedupe by protocol+IP (off: IP only)
debug_mode               = false  # verbose logging, includes probe bytes
port_sharing             = true   # SO_REUSEADDR on shared ports
onvif_verbatim           = false  # WSDiscovery: raw ONVIF payload
dahua_net_scan           = false  # Dahua subnet scan (Dahua2 netscan)
arp_enabled              = false  # ARP/GARP L2 engine (Rust-only)
```

### Permissions and graceful degradation

- The ARP engine captures raw frames: Linux needs `CAP_NET_RAW` (or root), macOS needs read
  access to `/dev/bpf`. Without it, the engine logs `warn: ARP discovery disabled (no capture
  permission)` and every other engine keeps running — which is also why `arp_enabled`
  defaults to off.
- If a port is already in use and `port_sharing` is off, that socket is skipped with a warning
  (same as C#). One busy port never fails the whole scan.

### OUI vendor annotation

MAC rows reported by the ARP engine get a vendor suffix, e.g.
`84:7b:57:xx:xx:xx (Intel Corporate)`. Lookup order: system `ieee-data` package →
`~/.cache/uscan/oui.txt` (via `uscan update-oui`) → a compressed database embedded in the
binary (~407 KB, 39,982 IEEE entries), so annotation works out of the box. Refreshing the
embedded database: `universal-scanner/src/oui_data/README.md`.

## Protocol engines

`uscan list-protocols` prints this same table. Registry IDs are inherited from the C# original
(they also fix the selftest source addresses `240.0.<id>.<minor>`); IDs 21/22/27 are the
C#-disabled Dlink / Hid / Microsens slots and are not implemented here.

| ID | Engine | Port | Listen | |
|---:|---|---|---|---|
| 1 | SSDP | 1900 | multicast 239.255.255.250:1900 | UPnP rootdevice |
| 2 | WSDiscovery | 3702 | multicast 239.255.255.250:3702 | WS-Discovery / ONVIF probe |
| 3 | Dahua | 5050 | global + ifaces :5050 | legacy probe |
| 4 | Dahua | 37810 | multicast 239.255.255.251:37810 | subnet scan (netscan) |
| 5 | Hikvision | 37020 | multicast 239.255.255.250:37020 | |
| 6 | Axis | 5353 | mDNS broker | |
| 7 | Bosch | 1758 | global + ifaces :1758 | video server |
| 8 | Google | 5353 | mDNS broker | Chromecast |
| 9 | Hanwha | 7711 | global + ifaces :7711 | Samsung |
| 10 | Vivotek | 10000 | ifaces only :10000 | |
| 11 | Sony | 2380 | ifaces only :2380 | |
| 12 | Ubiquiti | 10001 | global + ifaces :10001 | UniFi |
| 13 | 360Vision | 3600 | global + ifaces :3600 | |
| 14 | NiceVision | 2007 | global + ifaces :2007 | |
| 15 | Panasonic | 10670 | global + ifaces :10670 | |
| 16 | Arecont | 5353 | mDNS broker | |
| 17 | GigEVision | 3956 | ifaces only :3956 | |
| 18 | VStarcam | 8600 | global + ifaces :8600 | |
| 19 | Eaton | 4679 | global + ifaces :4679 | IPM / UPS |
| 20 | Foscam | 10000 | global + ifaces :10000 | |
| 23 | Lantronix | 30718 | global + ifaces :30718 | also covers Vauban |
| 24 | Microchip | 30303 | global + ifaces :30303 | also covers GCE Electronics |
| 25 | Advantech | 5048 | ifaces only :5048 | |
| 26 | Eden | 8088 | global + ifaces :8088 | Eden Optima |
| 28 | CyberPower | 53566 | global + ifaces :53566 | UPS |
| 29 | MSSQL | 1434 | global + ifaces :1434 | SQL Server Browser |
| 30 | ARP | — | pcap L2 capture | ARP/GARP, Rust-only |
| 31 | TVT | 23456 | multicast 234.55.55.55/.56:23456 | MHED, reverse-engineered |

The mDNS broker itself has no registry ID.

## Library

```rust
use universal_scanner::{Config, Scanner, DeviceTable};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (mut scanner, mut rx) = Scanner::new(Config::default(), None, None)?; // all engines
    scanner.start().await?;    // bind sockets, spawn receive tasks
    scanner.scan()?;           // one probe round; returns immediately
    let mut table = DeviceTable::new(Config::default().force_generic_protocols);
    while let Some(d) = rx.recv().await {
        if let Some(d) = table.add(d, true, false) {  // dedupe + version preference
            println!("{:?}", d);
        }
    }
    scanner.stop().await?;
    Ok(())
}
```

`Scanner::new(config, protocols, pcap_out)` builds the engine set (the name filter is
case-insensitive; a typo lists the valid names). The lifecycle is restartable: each `start()`
creates fresh engine instances and a cancellation token, and `stop()` cancels and joins
everything.

## Testing

- `cargo test --workspace` — 268 tests, all passing (at the time of writing).
- `uscan selftest` — the offline regression. `universal-scanner/tests/fixtures/` holds 32
  fixtures: 30 are real captures from the C# repository, `Arp.selftest` is synthetic (a 42-byte
  GARP frame, no C# counterpart), and `TVT.selftest` is a sanitized capture from a live TVT
  device.
- Coverage (`cargo llvm-cov --workspace`): 92.57% of library lines (14,663 lines, 1,089
  uncovered). The uncovered core is documented, not aspirational: `arp/capture.rs` (pcap
  capture thread, needs root and a live interface), `netscan.rs` (a real 254-host sweep), and
  `engine.rs` glue (real socket sends).

## Layout

```
universal-scanner/     # library crate
  src/scanner.rs       # runtime: engine registry, start/scan/stop
  src/engine.rs        # ScanEngine trait, EngineContext
  src/devices.rs       # Device, DeviceTable (dedupe, version preference)
  src/net.rs           # socket wrappers: global / interface / multicast
  src/mdns.rs          # mDNS broker (DNS wire parse + domain registry)
  src/arp/             # ARP frame build/parse, pcap capture/inject
  src/protocols/       # 28 engines, one file each
  src/oui.rs           # IEEE OUI lookup
  src/selftest.rs      # fixture replay table
  src/tvt_provision.rs # TVT L2 set-IP packet
  tests/fixtures/      # 32 .selftest captures
uscan/                 # CLI crate
  src/cli.rs           # clap definitions
  src/run.rs           # scan loop: stream / rescan / timeout / signals
  src/output.rs        # table / csv / json / tsv renderers
  src/config.rs        # CLI > TOML > defaults merge
```

## Out of scope

- The WinForms UI: grid interaction, CSV dialog, double-click-to-browse, single-instance and
  update checks.
- Windows. The C# app's registry settings are replaced by TOML + CLI flags.
- The C#-disabled Dlink / Hid / Microsens protocols.
- The device-management and streaming layers from the C# project (ONVIF SOAP configuration,
  DHCP vendor options, HTTP/REST, RTSP, SIP/GB28181, cloud registration) — separate efforts,
  with ONVIF Profile T planned first.

## Provenance

- Original tool: [UniversalScanner (C#)](https://github.com/julienblitte/UniversalScanner) by
  Julien Blitte, LGPL-3.0. Its protocols were all reverse-engineered by packet observation
  (no decompilation), for interoperability.
- Design spec for this port:
  `../UniversalScanner/docs/superpowers/specs/2026-08-20-universal-scanner-rust-design.md`
  (lives in the C# repository tree).

## License

LGPL-3.0, same as the original. See [LICENSE](LICENSE).
