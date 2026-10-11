// Subscription refresh support: locate the provider's subscription URL,
// fetch the raw Clash config, patch its listener ports to the running
// kernel's, and hand it to the controller's PUT /configs hot-reload
// (mimics what SakuraCat's own "refresh" does, without its GUI).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aps::subscription {

// Clash for Windows active profile (parsed from list.yml):
// the profile file path, its subscription URL, and the CFW config dir.
struct ActiveProfile {
    std::wstring path;      // e.g. %USERPROFILE%\.config\clash\profiles\<t>.yml
    std::string url;        // subscription URL from list.yml
    std::wstring configDir; // %USERPROFILE%\.config\clash
};

// Parse list.yml: "index: N" picks the active file entry; its "url:" is the
// subscription. configDir defaults to %USERPROFILE%\.config\clash.
std::optional<ActiveProfile> findClashForWindowsActiveProfile(
    const std::wstring& configDir = L"");

// SakuraCat stores the subscription URL in <configDir>\.store.json
// (field "SubscriptionUrl"). configDir defaults to
// %USERPROFILE%\.config\com.vortex.helper.
std::optional<std::string> findSakuraCatUrl(const std::wstring& configDir = L"");

// The default SakuraCat config directory (used for config.yaml IO).
std::wstring sakuraCatConfigDir();

// HTTPS GET of the subscription (returns the raw Clash YAML).
bool fetchText(const std::string& url, std::string& yaml, std::string* err);

// Same fetch, routed through a local HTTP CONNECT proxy (a Clash kernel's
// mixed port): the provider sees its own node IP as the client — airports
// with IP-whitelisted subscription downloads accept that unconditionally
// while 403-ing the home IP (xmrth's documented policy, measured
// 2026-09-02). Same content guard; single attempt, no backoff (the caller
// retries direct first).
bool fetchTextViaProxy(const std::string& url, uint16_t proxyPort,
                       std::string& yaml, std::string* err);

// Content guard for fetched subscriptions: a real Clash config must contain
// a "proxies:" section and must NOT be an HTML page (subscription servers
// rate-limit and return 403 pages instead — measured: a fetched HTML page
// was merged into config.yaml and corrupted it).
bool looksLikeClashYaml(const std::string& text);

// Splits "https://host[:port]/path?query" into its connection parts. The
// request object MUST include the query string ("/path?query") — a previous
// implementation shared one buffer between path and query (WinHttpCrackUrl
// overwrote the path with the query) and every fetch silently requested
// "GET /?token=...", receiving the server's HTML page (2026-08-27 incident).
// Pure and unit-testable.
bool parseHttpUrl(const std::string& url, std::string* host,
                  std::string* pathAndQuery, bool* isHttps);

// Extracts IP-form DNS server addresses (host order) from a Clash config's
// dns section: the `default-nameserver:` and `nameserver:` lists (inline
// or block form, quoted entries stripped). These are the resolvers the
// kernel itself trusts — the engine queries them through the kernel's
// tunnel for unpoisoned answers, with NO hard-coded servers anywhere.
// Pure and unit-testable.
std::vector<uint32_t> parseDnsServerIps(const std::string& yaml);

// Patch the listener field in a raw sub config to the running kernel's
// port: "mixed-port: 7890" -> "mixed-port: <port>". Pure line edit;
// missing/other fields are left untouched.
std::string patchMixedPort(const std::string& yaml, int port);

// Extract the kernel's SOCKS listener port from a Clash config: the first
// top-level "mixed-port:", "port:", or "socks-port:" line (that order of
// preference — mixed-port is what mihomo forks serve HTTP+SOCKS on).
// Quotes and trailing comments are stripped. Returns 0 when the config
// carries no usable listener port. Data-driven: no provider-specific
// port numbers are assumed anywhere.
uint16_t parseMixedPort(const std::string& yaml);

// Merge a fresh raw sub config into the CURRENT running config, replicating
// the kernel GUI's own transformation (measured by diffing SakuraCat's
// config.yaml against the sub it loads):
//  - mixed-port patched to `mixedPort` (the kernel's running listener),
//  - mode: rule -> direct,
//  - external-controller line replaced with the existing config's value,
//  - every top-level section present in `existing` but NOT in the sub
//    (the GUI's additions — SakuraCat's tun: block) is appended verbatim.
// Result is a complete, loadable config.yaml.
std::string mergeIntoExisting(const std::string& sub, const std::string& existing,
                              int mixedPort);

// Merge a fresh sub into a CFW profile file: replace the top-level
// proxies: section with the sub's, and regenerate the first inline
// url-test group's node list (CFW's "自动选择" carries EVERY proxy name —
// a stale list breaks the profile). Pure text transform.
std::string mergeCfwProfile(const std::string& sub, const std::string& profile);

// Read <dir>\config.yaml (UTF-8).
bool loadConfigFile(const std::wstring& dir, std::string& yaml, std::string* err);
// Atomic write of <dir>\config.yaml (temp + rename, like saveConfigFile).
bool saveConfigFile(const std::wstring& dir, const std::string& yaml,
                    std::string* err);

// Generic file read/write for CFW profile files (atomic + .bak on write).
bool loadTextFile(const std::wstring& path, std::string& text, std::string* err);
bool saveTextFile(const std::wstring& path, const std::string& text,
                  std::string* err);

// Restart the kernel that listens on `port` (loopback or any): resolves the
// owning PID, refuses anything that is not a known kernel image, terminates
// it, waits for the wrapping service (WinSW <onfailure action="restart"/>)
// to respawn it — and when nothing comes back, starts the kernel directly
// from the service.xml launch command line. Also starts the kernel when it
// is not running at all. Returns false + err otherwise.
bool restartKernelOnPort(uint16_t port, const std::wstring& configDir,
                         std::string* err);

}  // namespace aps::subscription
