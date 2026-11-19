// Discover loopback SOCKS5 outlets and their optional Clash controllers.
// The listening process owns the endpoint. Launcher names are for display.
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace aps {

enum class ProxyPortKind { Mixed, Socks };

struct DiscoveredKernel {
    uint32_t pid = 0;
    std::string procName;     // e.g. "clash-win64.exe", "com.vortex.helper.exe"
    uint16_t socksPort = 0;   // SOCKS5/mixed port (0 = none found)
    uint16_t apiPort = 0;     // controller port (0 = none found)
    bool apiNeedSecret = false;
    std::string apiSecret;    // read from the owning kernel's config and verified
    // Identity: two DIFFERENT kernels can share one image name (measured:
    // SakuraCat runs a main backend `-f config.yaml -ext-ctl ...:39798` plus
    // a second backend `-ext-ctl ...:39797`). The config dir (from `-d` or
    // the dir of `-f`) plus the controller port disambiguate them, and the
    // id assignment in the engine turns same-name instances into distinct
    // rows ("auto-<name>", "auto-<name>#2", ...) that never overwrite each
    // other's ports.
    std::string configDir;    // kernel's config directory ("" = unknown)
    std::string cmdline;      // full in memory; DPAPI at rest ("" = unknown)
    std::string id;           // stable id: "auto-<procName>", "#2"/"#3" for extra instances
    std::string apiPipe;      // local HTTP controller pipe; mutually exclusive with apiPort
    std::string discoveryError; // verified core with no usable SOCKS listener
    std::string launcherName;  // same-directory parent, when observable
    uint16_t conflictPort = 0;
    uint32_t conflictOwner = 0;
    ProxyPortKind conflictKind = ProxyPortKind::Mixed;
    std::string repairMessage;
    bool hasApi() const { return apiPort != 0 || !apiPipe.empty(); }
};

// Recheck the conflicting owner and controller, change only the runtime
// inbound, then verify SOCKS and ownership. Discovery by itself stays read-only.
bool repairConflictingProxyPort(DiscoveredKernel& kernel, uint16_t preferredPort = 0);

enum class DiscoveryMode {
    Quick,  // changed listeners and live candidates; revalidate on manual tests
    Changed, // periodic tick may reuse healthy results with unchanged ownership
    Full,   // probe every loopback listener (fallback; finds unknown kernels)
};

// Scans the machine and returns every discovered kernel. Read-only and
// side-effect free (short probes only). Per-probe timeouts are clamped to
// [50, 250] ms (localhost kernels answer in milliseconds; anything slower is
// just a silent listener burning scan time). Probes run as flat tasks on a
// small worker pool.
//
// One snapshot per engine, updated only after a completed scan. A stateless
// call starts from an empty baseline and verifies current endpoints.
struct DiscoverySnapshot {
    std::map<uint32_t, std::string> names;
    std::map<uint32_t, std::vector<uint16_t>> ports;
    std::set<uint32_t> retry;
    struct Observed {
        DiscoveredKernel kernel;
        uint64_t creationTime;
    };
    std::map<uint32_t, Observed> observed;
};
std::vector<DiscoveredKernel> discoverProxyKernels(
    int timeoutMs = 500, DiscoveryMode mode = DiscoveryMode::Quick,
    DiscoverySnapshot* previous = nullptr);

// --- persistent cache ------------------------------------------------------
// Remembers process names, stable outlet IDs and instance/controller hints.
// Automatic TCP ports are discovered from current listeners, never persisted.
// Legacy ports are read once as migration hints and removed on adoption, even
// if no kernels are running. Secrets/launch lines remain DPAPI-protected. File:
// %LOCALAPPDATA%\AppProxySwitch\kernel_cache.json
std::vector<DiscoveredKernel> loadKernelCache();
void saveKernelCache(const std::vector<DiscoveredKernel>& kernels);
// Merge adopted discoveries by stable ID/verified controller identity; keep
// offline names without ports. Empty results also migrate legacy caches.
// Discovery itself stays side-effect free.
void mergeDiscoveredIntoCache(const std::vector<DiscoveredKernel>& fresh);
// Test dependency injection, set before starting any scanner/engine threads.
// Empty restores the production location. Does not change user configuration.
void setKernelCacheDirectoryForTests(const std::wstring& directory);

// --- cheap helpers for the restarted-kernel fast path ----------------------
// Probe only `ports` for one PID (sequential; for cached ports and restarted
// kernels — few ports, no need for the parallel pool).
DiscoveredKernel probePidPorts(uint32_t pid, const std::vector<uint16_t>& ports,
                               int timeoutMs = 250);
// All loopback/any-bound LISTENING ports currently owned by `pid`.
std::vector<uint16_t> listeningPortsOf(uint32_t pid);
// True when SOME process currently LISTENS on this port (127.0.0.1 or
// INADDR_ANY). One cheap table query — used to decide whether a configured
// port is still live before auto-redirecting the default egress elsewhere.
bool hasLoopbackListener(uint16_t port);
// Process image name for one PID ("" when gone).
std::string processNameOf(uint32_t pid);
// Full command line of a process (read from its PEB; "" when inaccessible).
// Used to derive the kernel's config directory — the disambiguator between
// same-named kernel instances.
std::string processCommandLine(uint32_t pid);
// Conservative identity hint shared by differently named service/sidecar
// pipes. Derived from a long instance token, never a version/mode prefix.
// Must only be used after the endpoint's server PID and /version are verified.
std::string controllerPipeInstanceKey(const std::string& pipe);
// Extracts the kernel's config directory from a command line: the value of
// `-d <dir>`, else the parent directory of `-f <config.yaml>`, else "".
// Pure and unit-testable.
std::string parseConfigDirFromCmdline(const std::string& cmdline);
// PIDs of running processes whose image name contains any of `tokens`
// (case-insensitive; used to spot proxy kernels that restarted).
std::vector<uint32_t> findProcessIdsByName(const std::vector<std::string>& tokens);

// Reads the CFW controller secret from %USERPROFILE%\.config\clash\config.yaml.
// Returns "" when not found/readable (kernel then works only if unsecured).
std::string readCfwSecret();

}  // namespace aps
