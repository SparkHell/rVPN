# rVPN Core

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

rVPN is a stealth VPN with end-to-end encryption. Traffic is encrypted on your device and decrypted only by its destination. The relay server in between forwards ciphertext it cannot read.

This repository contains the core Rust implementation: the client, server, protocol libraries, and mobile FFI bindings. The native macOS, iOS, and Android apps are maintained separately.

## Architecture

- **Double Ratchet Algorithm** (from Signal) for continuous key rotation and forward secrecy
- **X3DH key exchange** for initial handshake without passwords or accounts
- **WebSocket over TLS** transport - traffic is indistinguishable from normal HTTPS
- **Pooled multiplexing** - many flows share a small set of long-lived connections, with credit-based flow control and TLS session resumption
- **Reverse proxy** - the server hosts a real website on port 443, the VPN endpoint is hidden behind it
- **Per-instance decoy pages** - plain HTTPS probes get a realistic, randomly chosen login page, so no two servers present the same face
- **TLS fingerprint mimicry** - connections mimic Chrome, Firefox, or Safari fingerprints
- **Web control panel** - embedded React UI with live WebSocket statistics and complete client configuration editing

## Repository Structure

```
rvpn/
  Cargo.toml         Workspace manifest
  Cargo.lock         Dependency lockfile
  crates/
    rvpn-core/       Protocol, cryptography, packet handling
    rvpn-client/     CLI client binary (SOCKS5 and TUN modes)
    rvpn-server/     Server binary (relay, NAT, TUN)
    rvpn-mobile/     FFI bindings for iOS/macOS/Android
```

## Building

The `rvpn` workspace uses Rust 1.100.0, pinned in `rvpn/rust-toolchain.toml`.
Its declared minimum supported Rust version remains 1.75.

```bash
cd rvpn

# Build everything
cargo build --release

# Build specific package
cargo build --release --package rvpn-client
cargo build --release --package rvpn-server
cargo build --release --package rvpn-mobile

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

### Build artifacts and releases

Pushes and pull requests build client/server binaries and retain them as Actions
artifacts. Pushes, scheduled builds, and manual runs on `main` update a single `nightly`
tag and prerelease, replacing assets with the same names. After a successful
nightly upload, older generated `nightly-YYYYMMDD-RUN_ID` prereleases and their
tags are removed. Other version tags and releases are preserved.

Publishing a GitHub Release builds its tagged commit and uploads the matching
platform archives and checksums to that release. Rerunning the workflow replaces
same-name assets without creating another release or version tag.

Client archives and Actions artifacts include `client.toml.example`; server
archives and artifacts include `server.toml.example`. Copy the example to
`client.toml` or `server.toml` and adjust it before starting. The originals live
under `config/`, and changes there trigger a new build.

Each platform also uploads a separate `build-timings-*` Actions artifact with
Cargo's HTML compilation reports. Cache exact-match status appears in the job
summary. These diagnostics are separate from release archives.

Release packaging checks the executable for each platform before uploading
archives. Linux x86_64 and ARM64 have no ELF interpreter or shared-library
dependencies. Windows x86_64 statically links the C/C++ runtime and imports
only Windows system DLLs at load time. The optional Windows TUN mode loads
the Wintun driver separately. macOS Intel and Apple Silicon use only Apple
system libraries and frameworks for dynamic linkage.

Configuration tests use the `ci-test` profile, with optimization, debug symbols,
LTO, and incremental compilation disabled. Dependency caches retain both the
release and test profiles; the first run with a new cache key warms both sets.
To run the same checks locally:

```bash
cd rvpn
cargo test --profile ci-test --locked -p rvpn-client --bin rvpn config::tests
cargo test --profile ci-test --locked -p rvpn-server --lib config::tests
```

### Embedded client control panel

Enable the panel and open `http://127.0.0.1:9800`:

```toml
[dashboard]
enabled = true
listen_address = "127.0.0.1:9800"
```

The client prints the browser URL after the listener starts, including the actual
port. Wildcard listeners print a loopback URL plus LAN access instructions. When
the panel is disabled, startup logs explain how to enable it.

The React + Tailwind CSS interface follows `DESIGN.md` and is built with Vite 8.
The HTML, JavaScript, CSS and fonts are embedded into `rvpn`; deployment needs
only the binary. No Node installation or CDN is needed at runtime.
WebSocket `/ws` pushes statistics every two seconds and handles configuration
reads, validation and saves. All existing fields have forms, including extra
servers and per-server routing. The old `/api/stats.json` endpoint remains.

Saving validates the settings and atomically replaces the same TOML or JSON
file passed to `-c`. Relative paths stay relative. Formatting and comments are
normalized when saving; unknown fields are retained. A revision check prevents
overwriting edits made by another page or program. **Save and apply** updates
the running client without restarting its process or system service. Log level,
log files and panel settings update independently, preserving VPN connections.
Other settings replace the network runtime, releasing old listeners and tasks;
existing proxy connections may disconnect and must reconnect. The worker-thread
count, DNS resolver/cache, routing, keys, data directory, proxy ports and TUN mode
are rebuilt from the new configuration. If startup or binding fails, the client
restores the old network configuration and configuration file and reports the
error. The overview shows the active configuration, rather than unconfirmed edits.
CLI overrides still take precedence, including when applying saved settings.

Changing the panel address binds the new listener and the page switches to that
address after receiving the save acknowledgement. Disabling the panel closes its
listener and WebSocket sessions; proxying continues. CIDR changes apply to new
and existing sessions. If VPN startup fails, an enabled panel stays available to
fix the settings; saving a corrected configuration starts the network again.
Externally edited files are shown as pending until saved/applied through the UI.

The existing `allow_cidrs` defaults to localhost. Allowed clients can read and
change all settings, including proxy credentials, so only allow trusted devices.
The listener verifies Host and WebSocket Origin, bounds message sizes and does
not enable CORS. Access the configured IP or `localhost`; arbitrary hostnames
and reverse-proxy origins are deliberately rejected.

Frontend development (Node 24 recommended):

```bash
cd rvpn/webui
npm ci
npm test
npm run build
npm run dev
```

The dev server proxies `/ws` to the client on port 9800. `npm run build` generates
`rvpn/crates/rvpn-client/ui-dist/index.html`; rebuild before compiling Rust after
UI edits. The generated asset is included for offline Cargo builds. CI builds
and tests the frontend once, then embeds that same artifact in every platform
binary. Browser tests use `npx playwright install chromium` and `npm run test:e2e`.

### Configuration paths

For both client and server on Windows, Linux, and macOS, relative `--config` / `-c` paths are resolved
from the executable's directory, independently of the terminal's current
directory. `client.toml` and `./client.toml` both refer to the file beside the
executable. Defaults are `client.toml` and `server.toml` in their respective executable directories. Absolute paths are
used directly.

Relative paths inside TOML/JSON configurations (identity keys, prekey bundles,
extra-server bundles, routing rules, known hosts, and an explicitly relative
`data_dir`) are resolved from the configuration file's directory. Both
`identity.key` and `./identity.key` work. For example:

```toml
identity_key_file = "./identity.key"
prekey_bundle = "./prekey-bundle.json"
```

The `--bundle` CLI override resolves relative to the executable's directory.
Missing configuration/key errors include the resolved file path.

The server uses the same configuration-directory rule for `tls_cert_file`,
`tls_key_file`, `identity_key_file`, `prekey_bundle_file`, `decoy_root`, and
`acme.cache_dir`. Both `[server]` sections and root-level TOML/JSON are supported.
For example:

```toml
[server]
tls_cert_file = "./certs/cert.pem"
tls_key_file = "./certs/key.pem"
identity_key_file = "./server_identity.key"
prekey_bundle_file = "./prekey-bundle.json"

[server.acme]
enabled = false
cache_dir = "./acme-cache"
```

Server `--identity`, `--rotate-from`, and explicit `--output` CLI overrides keep
their working-directory semantics. `keygen` and `prekey-bundle` can run without
a configuration; normal startup reports missing or invalid configurations.

### First-run key initialization

Normal startup automatically creates a missing client `identity_key_file`.
The client still needs the **server's public** `prekey-bundle.json`; it cannot
generate that file on the server's behalf. Missing bundle errors explain where
the file must come from.

Server startup initializes its identity and public bundle when deploying for
the first time. If `prekey_bundle_file` is omitted, it defaults to
`prekey-bundle.json` beside `server.toml`. The existing X3DH format also requires
`prekey-bundle.private.json`, which stores the server's private prekey. Keep
both private files on the server and distribute only the public JSON to clients.

Startup and generation logs show file paths, generated/loaded status, public
identity keys, fingerprints, and the bundle version. Private key contents are
never logged. New private files are published atomically without replacing existing
files; private files use mode `0600` on Linux/macOS. Parent directories are
created as needed.

Restarts preserve existing keys and bundles. Missing server identity or private
prekey files are generated automatically, and the public bundle is atomically
updated to match. Logs explicitly report identity changes and which public file
must be copied to clients. A new server identity requires previously pinned
clients to verify its new fingerprint. A missing public bundle is rebuilt from
the existing keys and any stored bundle metadata. Corrupt existing files or
inconsistent complete key sets cause an explicit error. The `keygen` and
`prekey-bundle` commands remain available for explicit generation and rotation.

### Client system service

The CLI supports systemd on Linux, Windows Service Control Manager, and a
system LaunchDaemon on macOS. Run these commands as root (Unix, for example with
`sudo`). Windows automatically requests UAC authorization for install, uninstall,
start, and stop when the terminal is not elevated:

```text
rvpn --config /absolute/path/client.toml service install
rvpn service start
rvpn service status
rvpn service stop
rvpn service uninstall
```

On Windows use a Windows path, for example
`rvpn.exe --config C:\rvpn\client.toml service install`.
Installation enables startup at boot; use `service start` to start immediately.
Install, uninstall, start, and stop print a confirmation on success; errors are
shown in the invoking terminal, including after Windows UAC elevation. Start
waits for client initialization and prints the actual WebUI URL when enabled
(including an automatically assigned port). If WebUI is disabled, it prints how
to enable it. VPN startup failures are shown even if WebUI remains available to
repair the configuration. Failed commands return a nonzero exit code.
Linux requires systemd. Service names are `rvpn-client` (Linux/Windows) and
`com.rvpn.client` (macOS). Installation does not copy the executable, config,
or keys: keep them at their installed paths. Relative paths in the configuration
are resolved from the configuration file's directory for all three platforms.
Put runtime settings in the configuration file; service installation rejects CLI
overrides. Services run as root/LocalSystem, so set an explicit writable `data_dir`
and ensure the service account can read the identity key and prekey bundle.
Unix logs are available through `journalctl -u rvpn-client` (Linux) or
`/var/log/rvpn-client.log` (macOS).

### Client and server file logs

The client displays startup errors directly on the console and opens its daily
log file once the network runtime is ready. The management-page URL also appears
on the console. Disable file logging to print runtime messages to the console.
The server writes startup errors and runtime messages to both the console and files.
Files are stored beside the executable on Windows, Linux, and
macOS, including when running as a service: `rvpn-client.YYYY-MM-DD.log` for the client
and `rvpn-server.YYYY-MM-DD.log` for the server. Dates use UTC, restarts append,
and up to seven matching log files are retained. Normal shutdown flushes queued
messages. The executable directory must be writable; if file creation fails, a
console warning explains the error and the program continues with console logs.

Configure the client with `[logging]`. For the server example's `[server]`
format, use `[server.logging]` (root-level server configs use `[logging]`):

```toml
[logging]
file_enabled = true
level = "info"       # off/error/warn/info/debug/trace; -v/-vv overrides
max_files = 7        # positive number of daily log files to retain
# directory = "./logs"
```

Omit `directory` to use the executable directory. An explicit relative directory
is resolved beside the configuration file, including `./` and `../`; absolute
directories are supported. Missing directories are created automatically.
Set `file_enabled = false` to keep console logging only.
The client's `-v`/`-vv` flags increase verbosity for rVPN modules; dependencies
such as HTTP/2 libraries remain at WARN/ERROR. Successful per-flow handshakes and
task completion are DEBUG, packet byte counts are TRACE, and ordinary heartbeat
frames do not emit a log line. File logs never contain terminal color codes.

### AdGuard and GFWList subscriptions

Open **分流规则** in the client panel to switch AdGuard domain filtering and GFWList
proxy rules independently. With split routing enabled, unmatched DNS queries use the local upstream. For connections, target IPs in the configured direct ranges connect directly. If direct regions are configured, other addresses use the VPN. Explicit tunnel domains and CIDRs take precedence. Save to apply switches. Each update button downloads through the client’s active SOCKS5 listener. AdGuard updates fetch both Hostlists Registry lists (DNS filter and AdAway hosts), then merge and validate them before replacing the snapshot. Each successful update atomically replaces the
snapshot under `data_dir/subscriptions`. Successful updates take effect on the
next routing decision and survive restarts. The bundled rules work offline
before the first update. AdGuard imports domain blocking and exception rules.
The existing custom ad block file remains available with ad blocking enabled.

DNS statistics count completed queries received by the local DNS proxy. The
percentages use all completed queries as the denominator. The panel keeps the
latest 64 results in process memory and displays up to six answers per query.

CI downloads and validates the upstream GFWList during the shared rule-data
build, converts its domain rules, then embeds `gfwlist-rules.json` into all
platform binaries. CI also embeds the merged advertising domains from both lists. The raw `filter_1.txt`, `filter_2.txt`, and GFWList source accompany the generated snapshots in every client artifact. The exact same data is included in every client archive's
`rules/` directory: raw `gfwlist.txt`, normalized `gfwlist-rules.json`, plain
`gfwlist-domains.txt`, source hashes/counts, and `LICENSE-GFWList.txt`. Publishing
reuses that artifact instead of fetching a different list after compilation.
A validated snapshot is tracked for offline/local Cargo builds. Updating the
program updates the built-in snapshot; `auto_reload_interval` continues to
reload custom rule files without changing this embedded data.

The build parser supports domain names, `.domain`, `||domain`, `||domain^`, and
`@@` domain exceptions. Matches include subdomains. URL/path, regex and wildcard
rules are counted and skipped rather than expanded into entire domains. This is
a domain import, not a complete AutoProxy URL matcher. Exceptions cancel only
GFWList matches and return to normal routing, without forcing a direct route.
Explicit user tunnel/bypass rules retain priority. The plain export omits
parents overlapping exceptions; the embedded JSON retains both sets.

VPN endpoints from `server_address` and every `[[server]].address` automatically
use direct routing in SOCKS5/HTTP/DNS modes, even when split tunneling is disabled
or a tunnel/block rule would otherwise match. This covers exact endpoint
hostnames and IPv4/IPv6 addresses; resolved endpoint IPs are refreshed before
transport connections. Rule-file reloads retain these exemptions, and changing
server configuration rebuilds them. No manual bypass-list entry is needed.

Other SOCKS5/HTTP targets matching an explicit proxy domain or GFWList go straight to the tunnel, preserving the hostname for remote DNS.
They no longer perform a local IP probe first. DNS-proxy A queries use the tunnel
too; VPN server hostnames retain local bootstrap resolution. The current DNS
tunnel supports address lookups only: AAAA returns NODATA, and non-address types
such as TXT/MX/HTTPS still use the configured local upstream. Merely enabling the
DNS listener does not change the operating system's DNS settings.

### Client TLS trust

Desktop VPN connections load CA certificates from the Windows certificate
store, macOS Keychain, or Linux system CA bundle. BoringSSL still performs
certificate-chain and hostname verification and provides the Chrome TLS
fingerprint. No separate CA file is needed for certificates trusted by the OS.
The trust anchors are loaded once per process; restart the client after changing
system trust settings. `SSL_CERT_FILE` / `SSL_CERT_DIR`, when set, override the
system certificate source. An empty or unusable trust store causes a connection
error. DNS, SOCKS5, and HTTP proxy connection errors include the underlying error
chain so certificate failures remain visible.

### Client DNS over HTTPS

DNS upstreams are configured directly in `dns_proxy.nameservers`. Use an
IP address (optionally with a port) for UDP, or an HTTPS URL for DoH. Replace the example addresses below with your DNS
provider's endpoints.

```toml
[dns_proxy]
enabled = true
listen_address = "127.0.0.1:53"
nameservers = ["https://dns.example.com/dns-query", "https://backup-dns.example.com/dns-query"]
```

UDP and DoH entries can be mixed, for example
`nameservers = ["https://dns.example.com/dns-query", "192.0.2.53:53"]`.
Upstreams are tried in configured order. To prevent plaintext fallback, list
only DoH URLs. No extra UDP resolver or system resolver is used when a list
containing DoH fails to resolve a requested name. DoH URLs accept IP addresses
and hostnames. The OS resolver resolves the DoH server's hostname when opening
a connection, while HTTPS verifies the original hostname. If the OS sends
that lookup back to rVPN, the DNS proxy tries only configured IP-based
upstreams for that lookup. Keep one reachable IP-based upstream in the list
when using rVPN as the system DNS. Requests use wire format POST with HTTP/2
support, a five-second timeout, no redirects, and no environment HTTP proxy.

These nameservers also serve client-side split-tunnel, direct connection, and
VPN endpoint lookups. Legacy `network.dns_servers` and `network.prefer_ipv4`
are ignored. Hostname lookups prefer IPv6 when enabled and keep IPv4 available
as a fallback. Record TTLs take precedence over the fallback TTL used for
system address lookups that return no record TTL.

Set `[network].ech_mode = "required"` to require ECH or `ech_mode = "prefer"` to prefer Encrypted ClientHello on the
desktop CLI's VPN WebSockets. The client reads the VPN endpoint's HTTPS and
address records using the HTTPS entries in `dns_proxy.nameservers`. Use the
VPN endpoint hostname as SNI. The TLS frontend can issue an authenticated
ECH retry config. If HTTPS/ECH discovery or the ECH handshake fails, the
client stops in required mode. In prefer mode it logs the reason and retries the original endpoint with standard TLS
and certificate verification before upgrading to WebSocket. Legacy `require_ech = true` selects prefer mode and `false` selects off.

Run with `-v` for per-stage timing. The logs distinguish endpoint address
and HTTPS lookups, TCP, TLS, WebSocket upgrade, X3DH and TUN address
assignment. TUN and SOCKS5 also report time to the first inbound data. The
dashboard handshake counters continue to report authentication outcomes.

To run the local SOCKS5 regression against built client and server binaries:

```sh
python3 scripts/test_endpoint_roundtrip.py --client rvpn/target/ci-test/rvpn \
  --server rvpn/target/ci-test/rvpn-server --caddy /path/to/caddy
```

The script uses temporary credentials and a loopback echo server. It checks
the returned payload, then stops and restarts the server and checks
recovery. Omit `--caddy` to run the direct case only.

The optional local `[dns_proxy]` listener still accepts UDP queries from apps;
DoH changes its local upstream transport. Tunnel-routed A/AAAA queries keep
the existing encrypted WebSocket DNS path. In TUN mode, tunneled DNS packets
keep their existing forwarding path; this setting controls client-side lookups
and does not replace the remote server's resolver.

### Cross-compilation

Install [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and [zig](https://ziglang.org/):

```bash
# macOS (Apple Silicon)
cargo zigbuild --release --target aarch64-apple-darwin

# macOS (Intel)
cargo zigbuild --release --target x86_64-apple-darwin

# Linux x86_64
cargo zigbuild --release --target x86_64-unknown-linux-gnu

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-gnu

# Linux ARMv7
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf

# Linux musl (static)
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

### Desktop CLI builds

On Windows with the MSVC Rust toolchain installed, build the command-line client:

```powershell
cd rvpn
cargo build --release --locked --package rvpn-client --package rvpn-server --bins
.\target\release\rvpn.exe --help
.\target\release\rvpn-server.exe --help
```

The [CLI build workflow](.github/workflows/cli-client.yml) builds Windows
x86_64, Linux x86_64/ARM64, and macOS Intel/Apple Silicon clients and servers.
The client (`rvpn`) and server (`rvpn-server`) are separate executables. Each
platform job uploads separate client and server artifacts with checksums. Use
SOCKS5 mode with the same client configuration as other desktop builds.

The workflow runs on relevant pushes, pull requests, and manual dispatch. After
all platform jobs pass on `main`, it publishes separate client and server
archives plus `SHA256SUMS.txt`, replacing the fixed `nightly` prerelease. It also rebuilds
and publishes nightly at 02:00 UTC even when no source files changed.
Windows TUN mode requires a compatible TUN driver and elevated privileges;
the workflow checks CLI startup, not a live VPN connection. The server's
automatic TUN route setup currently uses Linux `ip` commands, so server TUN
mode also needs platform-specific routing work outside Linux.

### Mobile library

The `rvpn-mobile` crate produces a static library (`librvpn_mobile.a`) for linking into native iOS, macOS, and Android apps. Build it with the appropriate feature flag:

```bash
# iOS
cargo build --release --package rvpn-mobile --target aarch64-apple-ios --features ios-direct-tun

# macOS
cargo build --release --package rvpn-mobile --target aarch64-apple-darwin --features macos-direct-tun

# Android
cargo build --release --package rvpn-mobile --target aarch64-linux-android --features android-direct-tun
```

The native app source code (Swift, Kotlin/Flutter) is not included in this repository.

### Routing rule data

The client first classifies proxied destinations by domain, then by resolved IP.
Configured tunnel domains and networks take priority over bypass lists; unmatched
traffic goes through the VPN. With `block_ads = true`, matching ad domains are
blocked before normal domain routing. The desktop CLI uses the shared
`rvpn-split-tunnel` rule engine for SOCKS5 and optional HTTP/DNS proxy modes.

The built-in data is a fixed snapshot: country CIDRs are attributed to APNIC,
China domains to `felixonmars/dnsmasq-china-list`, and ad domains to older
curated lists. Force-tunnel domains are maintained in this repository and have
no single upstream feed. Built-in data does not refresh itself.

Run the source-aware updater to create external rule files:

```bash
python3 scripts/update_rule_data.py --output-dir /var/lib/rvpn/rules
```

It downloads AdGuard DNS filter (`filter_1.txt`), AdAway hosts via AdGuard
(`filter_2.txt`), the China domain list, and APNIC delegations. It converts
domain-only blocking rules and hosts entries to plain domain names, and APNIC
records to `country-ips.json`. China domain candidates still require an IP
match in the selected country's CIDRs before bypassing the VPN. APNIC records
describe allocation country, not guaranteed current server location. URL/regex
rules and exceptions that cannot be represented by domain matching are skipped.
`sources.json` records source URLs,
SHA-256 hashes, update time, and rule counts. Every output file is staged and
replaced atomically after download and minimum-count validation; a failed
update leaves the previous files in place.

Point `client.toml` at the generated files:

```toml
[split_tunnel]
enabled = true
block_ads = true
ad_block_file = "/var/lib/rvpn/rules/ad-domains.txt"
country_ips_file = "/var/lib/rvpn/rules/country-ips.json"
builtin_bypass_countries = ["CN"]
auto_reload_interval = 3600
```

`block_ads = false` disables ad blocking even when the file is present.
`auto_reload_interval` rereads the files; it does not download new versions.
For automatic upstream updates, run the same command daily with cron or a
systemd timer. For example, `0 3 * * * /usr/bin/python3 /opt/rvpn/scripts/update_rule_data.py --output-dir /var/lib/rvpn/rules`.
The nightly client archives include the same generated files under `rules/`,
including source hashes and upstream license notices, plus `client.toml.example`.
Server archives contain the server executable, checksum, and `server.toml.example`.
Extracting a client archive under `/var/lib/rvpn`
provides the file paths used in the example above.
Run the updater once or extract a client archive before enabling these file
paths. If the country IP file later becomes unavailable, the client falls back
to its compiled-in CIDRs.

## Usage

### Generate keys

```bash
# Server identity key
cargo run --release --package rvpn-server -- keygen

# Server prekey bundle
cargo run --release --package rvpn-server -- prekey-bundle \
  --identity server_identity.key \
  --output prekey-bundle.json

# Client identity key
cargo run --release --package rvpn-client -- keygen --output identity.key
```

### Run the server

```bash
cargo run --release --package rvpn-server -- --config server.toml
```

### Run the client (SOCKS5 proxy mode)

```bash
cargo run --release --package rvpn-client -- --config client.toml
```

This starts a SOCKS5 proxy on `127.0.0.1:1080`. Configure your browser or system to use it.

Upgrade the server first when using legacy proxy mode. New desktop clients wait for an encrypted target-connection acknowledgement before granting SOCKS5 or HTTP CONNECT requests. Updated servers also accept the original legacy request format from older clients.

### Run the client (TUN mode, requires root)

```bash
sudo cargo run --release --package rvpn-client -- --config client.toml --tun
```

## Releases

Pre-built binaries for all platforms are published as GitHub releases on this repository. The native apps (macOS, iOS, Android) are distributed through their respective app stores.

## Documentation

Full documentation is at [docs.rvpn.org](https://docs.rvpn.org). The whitepaper is at [rvpn.org](https://rvpn.org).

## Licensing

rVPN is dual-licensed:

- **AGPL-3.0** for open-source use
- **Commercial license** for proprietary use, SaaS providers, or when AGPL obligations cannot be met

See [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).

Commercial licensing: license@pdg-global.com

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately to security@rvpn.org. See [SECURITY.md](SECURITY.md).

## About

PDG Global Limited (Hong Kong)

- Website: https://rvpn.org
- GitHub: https://github.com/PDG-Global/rVPN-core
