# AppProxySwitch

Per-application network routing for Windows. Route selected applications' TCP
connections through a local SOCKS5 endpoint, with independent rules, multiple
outlets, automatic core discovery, and an active connections view.

Current version: **1.3.0**.

## Downloads

The [1.3.0 release](https://github.com/ltmroberthk915/AppProxySwitch/releases/tag/v1.3.0)
provides a Windows x64 installer and a portable ZIP. Stop the engine and exit
from the tray before upgrading.

## Changes in 1.3.0

- Offline cores show their names without old ports. Duplicate unbound history
  is grouped; selected or explicitly rule-bound offline outlets remain visible.
- Automatic discovery cache v3 omits standalone SOCKS/API TCP port fields.
  Running instances are revalidated, with stable outlet IDs and automatic
  migration of older caches on the first scan.
- Node details have a vertical scrollbar and measured text wrapping. Mouse
  wheel, scrollbar dragging, and display scaling changes are supported.
- Includes idle receive heartbeats, runtime mode display, and read-only
  application routing diagnostics.

See the [release notes](docs/RELEASE-1.3.0-KERNEL-HISTORY-SCROLL.md) and
[validation record](docs/VALIDATION-1.3.0.md).

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
