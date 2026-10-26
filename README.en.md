# AppProxySwitch

**1.3.9 prerelease candidate:** External replies use explicit inbound injection and each flow's original interface. Native loopback keeps its original path, and synthesized resets no longer borrow cross-thread receive metadata. Incident causality and accelerator coexistence remain unverified. See [release notes](docs/RELEASE-1.3.9-TCP-RETURN-PATH.md).

The **1.3.7 GUI hotfix candidate** replaces the 1.3.6 GUI candidate. It removes intermediate control resets during status refresh, batches final rectangles and skips unchanged layout/text while preserving live counters. See [release notes](docs/RELEASE-1.3.7-REFRESH-JITTER.md) and [validation](docs/VALIDATION-1.3.7.md).

The **superseded 1.3.6 candidate** preserves window visibility during background layout and avoids duplicate restore requests. Control writes time out, cancel safely and reconnect; relay workers respond more promptly to cancellation under backpressure. Unsolicited window restoration and candidate model-stream stability still need live acceptance. See [candidate notes](docs/RELEASE-1.3.6-GUI-VISIBILITY.md) and [validation](docs/VALIDATION-1.3.6.md).

The **1.3.5 candidate** fixes relay configuration snapshots, worker cleanup and
socket cancellation races. It includes the earlier duplex and nested-selector
changes. See [candidate notes](docs/RELEASE-1.3.5-RELAY-LIFECYCLE.md).
Live model-stream stability still requires separate verification.

Per-application network routing for Windows. Route selected applications' TCP
connections through a local SOCKS5 endpoint, with independent rules, multiple
outlets, automatic core discovery, and an active connections view.

Current version: **1.3.2**.

## Downloads

The [1.3.2 release](https://github.com/ltmroberthk915/AppProxySwitch/releases/tag/v1.3.2)
provides a Windows x64 installer and a portable ZIP. Stop the engine and exit
from the tray before upgrading.

## 1.3.2 changes

- Explicit, default-empty TLS hostname allowlist recovers cached DNS addresses
  APS did not observe. Listed names use SOCKS DOMAIN; other names retain their
  DNS-correlation requirement.
- Selected outlets, TLS bytes and half-close behavior are preserved.
- Atomic configuration commands append or clear names without starting the
  engine or changing node preferences and encrypted credentials.
- Metadata logs explain hostname authorization and fallback to the original IP.

[Configuration and boundaries](docs/RELEASE-1.3.2-TLS-CACHED-DNS.md).
[Validation](docs/VALIDATION-1.3.2.md).

## Changes in 1.3.1

- Rule mode prioritizes configured GROUP preferences that identify active,
  rule-referenced service selectors, retaining the selector as the switch target.
- Node details identify the measured policy scope; changing scope clears stale
  latency and preference state.
- Relay logs record the first observed EOF side and timing, distinguish TCP
  completion from unverified application completion, and preserve half-close.
- Read-only diagnostics attribute connections by local socket ownership when
  process metadata is absent. TCP, named-pipe and shared diagnostic scripts ship
  with the release.

See the [release notes](docs/RELEASE-1.3.1-POLICY-MONITOR.md) and
[validation record](docs/VALIDATION-1.3.1.md).

## Usage

1. Start a local core with a SOCKS5 or mixed endpoint.
2. Select a discovered core and click the test/connect button, or enter a local
   endpoint manually.
3. Add applications, enable their rules, and start the engine.
4. Review destinations, rules, outlets, and connection status in the connections
   table. Stop the engine when finished.

The GUI runs without elevation; starting the engine requires UAC confirmation.
Rules can route, connect directly, or block new connections. Changes affect new
connections; an existing-connection disconnect action is also available.

## Scope

- TCP/IPv4, optional SOCKS5 authentication, path and version-directory wildcard
  matching, child processes, multiple outlets, and independently scrolling tables.
- Runtime discovery of Clash/Mihomo-compatible cores, including current
  listening ports, controller identity, and multiple instances.
- UDP, QUIC, IPv6, and ICMP are not forwarded. Configurable per-rule UDP/IPv6
  restrictions allow applications that support fallback to use TCP/IPv4.
- Windows system proxy and third-party TUN settings are not changed. Other
  applications' global network settings may still affect the selected program.
- No TLS decryption or application-body logging. Correlated TLS/DNS metadata
  can preserve a verified destination hostname. Controller delay measurements
  and SOCKS5 handshakes do not establish application reachability.
- Third-party configuration updates follow the client's own mechanisms;
  AppProxySwitch does not automatically change its mode or restart its core.

## Build

Windows 10/11 x64, Visual Studio 2022 C++ tools, and CMake 3.24 or newer:

```powershell
git clone https://github.com/ltmroberthk915/AppProxySwitch.git
cd AppProxySwitch
powershell -ExecutionPolicy Bypass -File scripts\fetch-windivert.ps1
powershell -ExecutionPolicy Bypass -File build-release.ps1
powershell -ExecutionPolicy Bypass -File scripts\run-tests.ps1 -Config Release
powershell -ExecutionPolicy Bypass -File package-release.ps1
```

The installer requires Inno Setup 6 and `package-installer.ps1`. Release builds
keep `APS_TEST_HOOKS=OFF`. WinDivert is fetched from its pinned official release
with SHA256 verification. See [design notes](docs/design.md).

## Data and license

Configuration and metadata-only logs are under
`%LOCALAPPDATA%\AppProxySwitch\`. Writes are atomic; passwords and controller
secrets use Windows DPAPI.

AppProxySwitch is [MIT licensed](LICENSE). The official unmodified WinDivert
files retain their LGPL/GPL dual license; see [third-party notices](LICENSES/NOTICE.md).

中文：[README.md](README.md).
