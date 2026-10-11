#include "aps/kernel_discovery.hpp"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

#include "aps/clash_api.hpp"
#include "aps/clash_pipe.hpp"
#include "aps/kernel_config.hpp"
#include "aps/dpapi.hpp"
#include "aps/json.hpp"
#include "aps/log.hpp"
#include "aps/net.hpp"
#include "aps/path_util.hpp"
#include "aps/socks5_client.hpp"
#include "aps/string_util.hpp"

// PEB read (command-line extraction) — undocumented but stable x64 layout.
// Resolved dynamically: no ntdll.lib link dependency.
#ifdef _WIN64
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG,
                                                 PULONG);
NtQueryInformationProcessFn loadNtQuery() {
    static NtQueryInformationProcessFn fn = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(
                           GetProcAddress(ntdll, "NtQueryInformationProcess"))
                     : nullptr;
    }();
    return fn;
}
#endif

namespace aps {

namespace {
std::wstring& cacheDirectoryOverride() {
    static std::wstring directory;
    return directory;
}
std::wstring kernelCacheDirectory() {
    return cacheDirectoryOverride().empty() ? appDataDir() : cacheDirectoryOverride();
}

// Built-in process-name hints for proxy kernels. Combined with names learned
// from previous scans (cache) to filter listening ports in Quick mode.
const char* const kKernelNameHints[] = {
    "clash",       // Clash for Windows (clash-win64.exe), original Clash
    "mihomo",      // Mihomo (clash.meta) standalone
    "v2ray", "xray", "sing-box", "singbox",
    "sakura",      // SakuraCat frontends
    "vortex",      // SakuraCat core (com.vortex.helper.exe)
    "verge", "nyanpasu", "flclash", "stash", "hiddify", "nekoray",
    "nekobox", "shadowsocks", "trojan", "hysteria",
    "surfboard", "proxycap", "proxifier",
};

// Never adopt as kernels: our own test binaries run in-process mock SOCKS/
// controller servers that would otherwise be discovered on a dev machine
// and pollute the persistent cache (observed in the wild: rows for
// "test_engine_harness.exe" in the node list). Disabled in TEST builds —
// the harness's own discovery tests depend on adopting their in-process
// mocks.
#ifdef APS_BUILD_TESTS
const char* const kKernelNameExcludes[] = {};
#else
const char* const kKernelNameExcludes[] = {
    "test_engine_harness", "test_kernel_discovery", "test_clash_api", "aps_test_client",
};
#endif

std::string lower(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s) r.push_back(static_cast<char>(std::tolower(c)));
    return r;
}

bool nameContains(const std::string& name, const std::string& needle) {
    return lower(name).find(lower(needle)) != std::string::npos;
}

int clampProbeTimeout(int timeoutMs) {
    return std::min(std::max(timeoutMs, 50), 250);
}

// PID -> process image name for every running process. Toolhelp snapshot
// needs no process handle rights, unlike OpenProcess-based lookups (which
// fail for elevated or protected processes).
std::map<uint32_t, std::string> processNameMap() {
    std::map<uint32_t, std::string> m;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char utf8[MAX_PATH * 3];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, utf8, sizeof(utf8),
                                nullptr, nullptr);
            m[pe.th32ProcessID] = utf8;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return m;
}

// All LISTENING 127.0.0.1 / 0.0.0.0 ports with owning PID, excluding system
// services. INADDR_ANY-bound listeners are included because several kernels
// bind their mixed port on all interfaces (e.g. SakuraCat's 7897) — a
// 127.0.0.1 connect still reaches them.
std::vector<std::pair<uint32_t, uint16_t>> enumerateListeners() {
    std::vector<std::pair<uint32_t, uint16_t>> out;
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                            0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<uint8_t> buf(size);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                if (row.dwState != MIB_TCP_STATE_LISTEN) continue;
                if (row.dwLocalAddr != 0x0100007Fu && row.dwLocalAddr != 0)
                    continue;  // 127.0.0.1 (net order) or INADDR_ANY
                if (row.dwOwningPid == 0 || row.dwOwningPid == 4) continue;
                out.emplace_back(row.dwOwningPid,
                                 ntohs(static_cast<uint16_t>(row.dwLocalPort & 0xFFFF)));
            }
        }
    }
    size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<uint8_t> buf(size);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6,
                                TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR) {
            auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                // Only wildcard IPv6 sockets can also accept IPv4. An IPv6-only
                // listener never passes our subsequent 127.0.0.1 handshake.
                bool any = std::all_of(std::begin(row.ucLocalAddr),
                                       std::end(row.ucLocalAddr), [](auto b) { return b == 0; });
                if (!any || row.dwOwningPid == 0 || row.dwOwningPid == 4) continue;
                const auto port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                // A v6-only socket may coexist with another PID's IPv4
                // listener. A successful IPv4 probe would prove the OTHER
                // process, so never attribute it to this IPv6-only owner.
                if (std::any_of(out.begin(), out.end(), [&](const auto& endpoint) {
                        return endpoint.second == port && endpoint.first != row.dwOwningPid;
                    })) continue;
                out.emplace_back(row.dwOwningPid,
                                 port);
            }
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

bool probeApiPort(uint16_t port, int timeout, bool* needSecret) {
    auto p = ClashApiClient("127.0.0.1", port, "").probeAny(timeout);
    if (!p.reachable) return false;
    if (needSecret) *needSecret = p.needSecret;
    return true;
}

bool probeSocksPort(uint16_t port, int timeout) {
    std::string err;
    return Socks5Client::probe(net::Endpoint4{0x7F000001, port}, timeout,
                               nullptr, &err);
}

// Enumerate names only; opening every pipe even with metadata-only access
// would consume other applications' pipe instances. Only observed names
// matching a proven SOCKS process's executable stem are probe candidates.
std::vector<std::string> localPipeNames() {
    std::vector<std::string> names;
    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(L"\\\\.\\pipe\\*", &data);
    if (search == INVALID_HANDLE_VALUE) return names;
    do {
        auto name = "\\\\.\\pipe\\" + wideToUtf8(data.cFileName);
        if (localControllerPipe(name)) names.push_back(std::move(name));
    } while (FindNextFileW(search, &data));
    FindClose(search);
    return names;
}

// Fill identity + auto-secret for a kernel that has at least one port.
void finishKernel(DiscoveredKernel& k) {
    k.id = "auto-" + lower(k.procName);
    if (!k.apiNeedSecret) return;
    auto launch = readKernelLaunchConfig(k.cmdline);
    auto secret = launch.secret;
    // Compatibility for CFW's protected core, whose command line may be
    // unreadable. Do not send CFW credentials to every Clash-family app.
    if (secret.empty() && lower(k.procName) == "clash-win64.exe") secret = readCfwSecret();
    if (!secret.empty()) {
        auto p = ClashApiClient("127.0.0.1", k.apiPort, secret, k.apiPipe, k.pid).probeAny(250);
        if (p.reachable && !p.needSecret) {
            k.apiSecret = std::move(secret);
            k.apiNeedSecret = false;
        }
    }
}

}  // namespace

std::string controllerPipeInstanceKey(const std::string& pipe) {
    if (!localControllerPipe(pipe)) return {};
    const auto split = pipe.find_last_of('-');
    if (split == std::string::npos) return {};
    auto key = lower(pipe.substr(split + 1));
    if (key.size() < 16 || key.size() > 128 ||
        !std::all_of(key.begin(), key.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        })) return {};
    // Development and production controllers can share a user token while
    // intentionally serving different configurations.
    const auto prefix = lower(pipe.substr(0, split));
    return (prefix.ends_with("-dev") || prefix.find("-dev-") != std::string::npos)
        ? "dev:" + key : key;
}

// ---------------------------------------------------------------------------
// Command-line identity (public: engine + tests use parseConfigDirFromCmdline)
// ---------------------------------------------------------------------------

std::string processCommandLine(uint32_t pid) {
    std::string cmdline;
#ifdef _WIN64
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return {};
    // PEB -> ProcessParameters -> CommandLine (offsets: x64 only; this build
    // is x64-only — WinDivert 2.2.2 and every Clash-family core are x64).
    struct PBI { PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2];
                 ULONG_PTR UniqueProcessId; PVOID Reserved3; } pbi{};
    ULONG retLen = 0;
    auto nq = loadNtQuery();
    if (nq && nq(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi),
                 &retLen) >= 0 &&
        pbi.PebBaseAddress) {
        constexpr size_t kPe = 0x20;   // PEB.ProcessParameters (x64)
        constexpr size_t kCl = 0x70;   // RTL_USER_PROCESS_PARAMETERS.CommandLine (x64)
        PVOID params = nullptr;
        SIZE_T read = 0;
        if (ReadProcessMemory(h, (const BYTE*)pbi.PebBaseAddress + kPe, &params,
                              sizeof(params), &read) && params) {
            struct Uni { USHORT Length; USHORT MaxLength; PWSTR Buffer; } u{};
            if (ReadProcessMemory(h, (const BYTE*)params + kCl, &u, sizeof(u),
                                  &read) && u.Buffer && u.Length) {
                std::vector<wchar_t> buf(u.Length / sizeof(wchar_t) + 1);
                if (ReadProcessMemory(h, u.Buffer, buf.data(), u.Length, &read)) {
                    buf[u.Length / sizeof(wchar_t)] = L'\0';
                    cmdline = wideToUtf8(buf.data());
                }
            }
        }
    }
    CloseHandle(h);
#endif
    return cmdline;
}

// Image path (exe location) for one PID — the identity fallback when the
// command line is unreadable (e.g. a protected core process). The exe dir
// is NOT the config dir, but it is a stable per-instance anchor for the
// registry matcher; real config dirs win whenever the PEB read succeeds.
std::string processImagePath(uint32_t pid) {
    std::string out;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return out;
    wchar_t buf[MAX_PATH] = {};
    DWORD n = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &n) && n > 0) {
        char utf8[MAX_PATH * 3];
        int m = WideCharToMultiByte(CP_UTF8, 0, buf, -1, utf8, sizeof(utf8),
                                    nullptr, nullptr);
        if (m > 0) out.assign(utf8, m - 1);
    }
    CloseHandle(h);
    return out;
}

std::string parseConfigDirFromCmdline(const std::string& cmdline) {
    return parseKernelLaunchConfig(cmdline).configDir;
}

// ---------------------------------------------------------------------------
// Persistent cache
// ---------------------------------------------------------------------------

namespace {
void assignCacheIds(std::vector<DiscoveredKernel>& kernels) {
    // Preserve the v1/v2 startup order when migrating, then retain those IDs
    // explicitly: changing random ports must not change an activated outlet.
    std::sort(kernels.begin(), kernels.end(), [](const auto& a, const auto& b) {
        if (lower(a.procName) != lower(b.procName)) return lower(a.procName) < lower(b.procName);
        const bool af = a.cmdline.find("-f ") != std::string::npos;
        const bool bf = b.cmdline.find("-f ") != std::string::npos;
        if (af != bf) return af;
        return a.apiPort < b.apiPort;
    });
    std::set<std::string> used;
    for (auto& k : kernels) {
        const std::string base = "auto-" + lower(k.procName);
        const std::string prefix = base + "#";
        const bool suffix = k.id.starts_with(prefix) && k.id.size() > prefix.size() &&
            std::all_of(k.id.begin() + prefix.size(), k.id.end(),
                        [](unsigned char c) { return c >= '0' && c <= '9'; });
        if ((k.id != base && !suffix) || !used.insert(k.id).second) k.id.clear();
    }
    for (auto& k : kernels) {
        if (!k.id.empty()) continue;
        const std::string base = "auto-" + lower(k.procName);
        k.id = base;
        for (int n = 2; used.count(k.id); ++n) k.id = base + "#" + std::to_string(n);
        used.insert(k.id);
    }
}
} // namespace

std::vector<DiscoveredKernel> loadKernelCache() {
    std::vector<DiscoveredKernel> out;
    std::wstring dir = kernelCacheDirectory();
    if (dir.empty()) return out;
    std::ifstream f(dir + L"\\kernel_cache.json", std::ios::binary);
    if (!f) return out;
    std::stringstream ss;
    ss << f.rdbuf();
    json::Value root;
    std::string err;
    if (!json::Value::parse(ss.str(), root, &err) || !root.isObject()) return out;
    const json::Value* arr = root.find("kernels");
    if (!arr || !arr->isArray()) return out;
    const bool legacy = !root.find("version") || root.find("version")->asInt() < 3;
    for (size_t i = 0; i < arr->size(); ++i) {
        const json::Value& o = arr->at(i);
        if (!o.isObject()) continue;
        DiscoveredKernel k;
        const json::Value* n = o.find("procName");
        if (!n || n->asString().empty()) continue;
        k.procName = n->asString();
        // Legacy ports are only migration hints for matching the first scan.
        // v3 never stores or restores automatic TCP endpoints.
        if (legacy) {
            if (const auto* sp = o.find("socksPort")) k.socksPort = static_cast<uint16_t>(sp->asInt(0));
            if (const auto* ap = o.find("apiPort")) k.apiPort = static_cast<uint16_t>(ap->asInt(0));
        } else if (const auto* id = o.find("id")) {
            k.id = id->asString();
        }
        // v2 fields (v1 caches lack them — loaded as empty, harmless).
        const json::Value* cd = o.find("configDir");
        if (cd) k.configDir = cd->asString();
        const json::Value* cl = o.find("cmdline");
        if (cl) k.cmdline = cl->asString();
        if (auto enc = o.find("cmdlineEnc")) k.cmdline = crypto::unprotectFromBase64(enc->asString(), nullptr);
        if (auto pipe = o.find("apiPipe")) {
            if (localControllerPipe(pipe->asString())) k.apiPipe = pipe->asString();
        }
        const json::Value* sec = o.find("apiSecret");
        if (sec && sec->isString() && !sec->asString().empty()) {
            bool ok = false;
            k.apiSecret = crypto::unprotectFromBase64(sec->asString(), &ok);
            if (!ok) k.apiSecret.clear();
            if (!k.apiSecret.empty()) k.apiNeedSecret = false;
        }
        out.push_back(std::move(k));
    }
    assignCacheIds(out);
    return out;
}

void saveKernelCache(const std::vector<DiscoveredKernel>& kernels) {
    std::wstring dir = kernelCacheDirectory();
    if (dir.empty() || !ensureDirectory(dir)) return;
    auto entries = kernels;
    assignCacheIds(entries);
    json::Value arr = json::Value::makeArray();
    for (const auto& k : entries) {
        if (k.procName.empty()) continue;
        json::Value o = json::Value::makeObject();
        o.set("procName", json::Value(k.procName));
        o.set("id", k.id);
        if (!k.configDir.empty()) o.set("configDir", json::Value(k.configDir));
        // Launch flags can include -secret; never persist raw command lines.
        if (!k.cmdline.empty()) o.set("cmdlineEnc", crypto::protectToBase64(k.cmdline));
        if (!k.apiPipe.empty()) o.set("apiPipe", k.apiPipe);
        if (!k.apiSecret.empty()) {
            std::string blob = crypto::protectToBase64(k.apiSecret);
            if (!blob.empty()) o.set("apiSecret", json::Value(blob));
        }
        arr.append(std::move(o));
    }
    json::Value root = json::Value::makeObject();
    root.set("version", json::Value(3));
    root.set("kernels", std::move(arr));

    // Atomic write (temp + rename), same pattern as saveConfigFile.
    std::string text = root.dump();
    std::wstring path = dir + L"\\kernel_cache.json";
    std::wstring tmp = path + L".tmp";
    HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    BOOL ok = WriteFile(f, text.data(), static_cast<DWORD>(text.size()), &written,
                        nullptr);
    BOOL flushed = FlushFileBuffers(f);
    CloseHandle(f);
    if (!ok || !flushed || written != text.size()) {
        DeleteFileW(tmp.c_str());
        log::w("kernel cache: write failed");
        return;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        log::w("kernel cache: atomic replace failed");
    }
}

void setKernelCacheDirectoryForTests(const std::wstring& directory) {
    cacheDirectoryOverride() = directory;
}

// Keep names and instance/credential hints, never historical TCP endpoints.
// Adopted IDs distinguish concurrent same-named kernels without stored ports.
// Called by the engine when it adopts discovery results — discovery itself
// stays side-effect free.
void mergeDiscoveredIntoCache(const std::vector<DiscoveredKernel>& fresh) {
    auto cache = loadKernelCache();
    for (const auto& k : fresh) {
        if (k.procName.empty()) continue;
        // A verified pipe is stronger identity than a directory: a service
        // launch can make the command line inaccessible, changing configDir
        // from the real user config to the executable-directory fallback.
        auto pipeMatch = std::find_if(cache.begin(), cache.end(), [&](const auto& c) {
            const auto key = controllerPipeInstanceKey(k.apiPipe);
            return lower(c.procName) == lower(k.procName) && !k.apiPipe.empty() &&
                   (lower(c.apiPipe) == lower(k.apiPipe) ||
                    (!key.empty() && controllerPipeInstanceKey(c.apiPipe) == key));
        });
        bool found = false;
        const auto idMatch = std::find_if(cache.begin(), cache.end(), [&](const auto& c) {
            return !k.id.empty() && c.id == k.id && lower(c.procName) == lower(k.procName);
        });
        if (!k.id.empty() && idMatch == cache.end()) {
            // Adoption has already separated concurrent instances. A new ID
            // must not overwrite another instance sharing the same directory.
            cache.push_back(k);
            continue;
        }
        for (auto& c : cache) {
            if (lower(c.procName) != lower(k.procName)) continue;
            // Same instance: config dirs agree (when known) or the API port
            // matches (CFW re-randomizes ports but SakuraCat pins the
            // controller port in its command line).
            bool sameDir = !k.configDir.empty() && k.configDir == c.configDir;
            bool sameApi = (k.apiPort != 0 && k.apiPort == c.apiPort) ||
                           (!k.apiPipe.empty() && lower(k.apiPipe) == lower(c.apiPipe));
            if (idMatch != cache.end()) {
                if (&c != &*idMatch) continue;
            } else if (pipeMatch != cache.end()) {
                if (&c != &*pipeMatch) continue;
            } else {
                // Two distinct pipe instances may use the same executable
                // directory. Never overwrite one based on that weak hint.
                if (!k.apiPipe.empty() && !c.apiPipe.empty() && !sameApi) continue;
                if (!sameDir && !sameApi) continue;
            }
            found = true;
            if (!k.id.empty()) c.id = k.id;
            if (k.socksPort) c.socksPort = k.socksPort;
            if (k.hasApi()) { c.apiPort = k.apiPort; c.apiPipe = k.apiPipe; }
            if (!k.apiSecret.empty()) c.apiSecret = k.apiSecret;
            if (!k.configDir.empty()) c.configDir = k.configDir;
            if (!k.cmdline.empty()) c.cmdline = k.cmdline;
            break;
        }
        if (!found) cache.push_back(k);
    }
    saveKernelCache(cache);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

std::vector<DiscoveredKernel> discoverProxyKernels(int timeoutMs,
                                                   DiscoveryMode mode) {
    const int t = clampProbeTimeout(timeoutMs);
    auto listeners = enumerateListeners();
    auto names = processNameMap();

    // Quick mode: probe only processes whose name matches a built-in kernel
    // pattern or a name the scanner has cached before. Enumerating the table
    // and resolving names takes milliseconds; the probes (a handful of ports)
    // finish near-instantly, unlike a blind scan of every loopback listener.
    // In Full mode the same list marks a name as KNOWN: unknown-name
    // processes must then prove themselves with BOTH ports (see assembly).
    std::vector<std::string> allowed;
    for (const char* h : kKernelNameHints) allowed.emplace_back(h);
    const auto cached = loadKernelCache();
    for (const auto& c : cached)
        if (!c.procName.empty()) allowed.push_back(c.procName);

    auto isAllowed = [&](const std::string& name) {
        for (const auto& tok : allowed) {
            if (nameContains(name, tok)) return true;
        }
        return false;
    };
    auto isExcluded = [&](const std::string& name) {
        // An explicitly isolated test scanner may discover its mock children.
        if (!cacheDirectoryOverride().empty()) return false;
        for (const auto* x : kKernelNameExcludes) if (nameContains(name, x)) return true;
        return false;
    };

    std::map<uint32_t, std::vector<uint16_t>> byPid;
    std::map<uint32_t, bool> knownPid;
    for (const auto& [pid, port] : listeners) {
        auto it = names.find(pid);
        if (it == names.end()) continue;
        if (isExcluded(it->second)) continue;
        if (!isAllowed(it->second) && mode == DiscoveryMode::Quick) continue;
        if (mode == DiscoveryMode::Full) knownPid[pid] = isAllowed(it->second);
        byPid[pid].push_back(port);
    }

    // Flat task pool: one task per (pid, port, probe-kind). Silent listeners
    // burn a full timeout each, so serial probing would take minutes; flat
    // tasks spread every probe across all workers.
    struct Task {
        uint32_t pid;
        uint16_t port;
        bool isApi;
    };
    std::vector<Task> tasks;
    for (const auto& kv : byPid) {
        for (uint16_t p : kv.second) {
            tasks.push_back({kv.first, p, true});
            tasks.push_back({kv.first, p, false});
        }
    }

    struct Slot {
        uint16_t socksPort = 0;
        uint16_t apiPort = 0;
        bool apiNeedSecret = false;
        std::string apiPipe;
    };
    std::mutex slotsMu;
    std::map<uint32_t, Slot> slots;
    std::atomic<size_t> next{0};
    size_t workersN = std::min<size_t>(tasks.size(), 8);
    std::vector<std::thread> workers;
    workers.reserve(workersN);
    for (size_t w = 0; w < workersN; ++w) {
        workers.emplace_back([&] {
            for (;;) {
                size_t i = next.fetch_add(1, std::memory_order_relaxed);
                if (i >= tasks.size()) return;
                const Task& task = tasks[i];
                if (task.isApi) {
                    bool needSecret = false;
                    if (probeApiPort(task.port, t, &needSecret)) {
                        std::lock_guard<std::mutex> lk(slotsMu);
                        Slot& s = slots[task.pid];
                        if (s.apiPort == 0) {
                            s.apiPort = task.port;
                            s.apiNeedSecret = needSecret;
                        }
                    }
                } else {
                    if (probeSocksPort(task.port, t)) {
                        std::lock_guard<std::mutex> lk(slotsMu);
                        Slot& s = slots[task.pid];
                        if (s.socksPort == 0) s.socksPort = task.port;
                    }
                }
            }
        });
    }
    for (auto& th : workers) th.join();

    // A pipe-only controller has no TCP listener to enumerate. Discover the
    // endpoint from the running process's actual launch arguments/config,
    // never a wrapper-specific directory or guessed pipe/port. Full mode
    // also checks unrecognized process names (including renamed cores).
    std::map<uint32_t, std::string> cmdlines;
    std::map<uint32_t, KernelLaunchConfig> launches;
    for (const auto& [pid, name] : names) {
        if (isExcluded(name) || (mode == DiscoveryMode::Quick && !isAllowed(name))) continue;
        auto cmd = processCommandLine(pid);
        auto flags = parseKernelLaunchConfig(cmd);
        // Ordinary app -f flags are not permission to crawl unrelated files.
        if (!isAllowed(name) && !slots.count(pid) && flags.pipe.empty()) continue;
        auto launch = readKernelLaunchConfig(cmd);
        cmdlines[pid] = std::move(cmd);
        launches[pid] = launch;
        if (!localControllerPipe(launch.pipe)) continue;
        auto p = ClashApiClient("127.0.0.1", 0, launch.secret,
                                launch.pipe, pid).probeAny(t);
        // For a pipe, require a valid /version response AND matching server
        // PID. A random app's 401 cannot create an API-only kernel row.
        if (!p.reachable || p.needSecret) continue;
        auto& slot = slots[pid];
        slot.apiPort = 0;
        slot.apiNeedSecret = false;
        slot.apiPipe = launch.pipe;
    }

    // Service-mode cores may expose their SOCKS listener while APS cannot
    // read their PEB/config. Recover a previously observed controller, or an
    // existing process-named pipe on a fresh machine. Neither is trusted by
    // name/cache: requestControllerPipe verifies the CURRENT server PID
    // before writing HTTP (or a secret), then /version must identify Clash.
    // Do not scan arbitrary application pipes or guess wrapper directories.
    std::vector<std::string> observedPipes;
    bool pipesEnumerated = false;
    for (const auto& [pid, launch] : launches) {
        auto slotIt = slots.find(pid);
        if (slotIt != slots.end() &&
            (slotIt->second.apiPort || !slotIt->second.apiPipe.empty())) continue;
        const auto& name = names.at(pid);
        std::vector<std::string> candidates;
        std::set<std::string> instanceKeys;
        if (const auto key = controllerPipeInstanceKey(launch.pipe); !key.empty()) instanceKeys.insert(key);
        for (const auto& c : cached) {
            if (lower(c.procName) == lower(name) && localControllerPipe(c.apiPipe)) {
                candidates.push_back(c.apiPipe);
                if (const auto key = controllerPipeInstanceKey(c.apiPipe); !key.empty()) instanceKeys.insert(key);
            }
        }
        if (slotIt != slots.end() && slotIt->second.socksPort) {
            if (!pipesEnumerated) {
                observedPipes = localPipeNames();
                pipesEnumerated = true;
            }
            auto stem = lower(name);
            if (stem.ends_with(".exe")) stem.resize(stem.size() - 4);
            const auto prefix = "\\\\.\\pipe\\" + stem;
            for (const auto& pipe : observedPipes) {
                const auto folded = lower(pipe);
                // Service/sidecar controllers now carry an instance suffix.
                // The name only selects a candidate: its CURRENT server PID
                // and a valid /version response still prove the association.
                const auto key = controllerPipeInstanceKey(pipe);
                if (folded == prefix || folded.starts_with(prefix + "-") ||
                    (!key.empty() && instanceKeys.count(key)))
                    candidates.push_back(pipe);
            }
        }
        std::set<std::string> tried;
        if (!launch.pipe.empty()) tried.insert(lower(launch.pipe));
        for (const auto& pipe : candidates) {
            if (!tried.insert(lower(pipe)).second) continue;
            auto p = ClashApiClient("127.0.0.1", 0, launch.secret, pipe, pid).probeAny(t);
            if (!p.reachable || p.needSecret) continue;
            auto& slot = slots[pid];
            slot.apiPort = 0;
            slot.apiNeedSecret = false;
            slot.apiPipe = pipe;
            break;
        }
    }

    // Assemble kernels from probe results.
    std::vector<DiscoveredKernel> kernels;
    for (const auto& kv : slots) {
        const Slot& s = kv.second;
        // A proxy kernel MUST have a SOCKS port. API-only responders are
        // ordinary local HTTP services (dev servers, app backends — measured
        // in the wild: node.exe, DSH Desktop.exe) — never adopt them.
        if (s.socksPort == 0 && s.apiPipe.empty()) continue;
        DiscoveredKernel k;
        k.pid = kv.first;
        auto nameIt = names.find(k.pid);
        if (nameIt == names.end()) continue;  // process exited mid-scan
        k.procName = nameIt->second;
        // Unknown-name processes (Full blind scan) must prove themselves
        // with BOTH ports; a lone SOCKS responder is more likely a generic
        // proxy tool than an airport kernel, and junk adoption pollutes the
        // persistent cache.
        if (mode == DiscoveryMode::Full && !knownPid[k.pid] &&
            s.apiPort == 0 && s.apiPipe.empty()) {
            continue;
        }
        k.socksPort = s.socksPort;
        k.apiPort = s.apiPort;
        k.apiNeedSecret = s.apiNeedSecret;
        k.apiPipe = s.apiPipe;
        if (!k.apiPipe.empty()) k.apiSecret = launches[k.pid].secret;
        // Identity fields: the command line carries the config dir (-d) and
        // the controller port (-ext-ctl) — the disambiguator between
        // same-named instances. When the PEB read fails (protected cores
        // like CFW's clash-win64), fall back to the exe dir: not the config
        // dir, but a stable identity anchor.
        k.cmdline = cmdlines.count(k.pid) ? cmdlines[k.pid] : processCommandLine(k.pid);
        k.configDir = parseConfigDirFromCmdline(k.cmdline);
        if (k.configDir.empty()) {
            std::string img = processImagePath(k.pid);
            if (!img.empty()) {
                size_t p = img.find_last_of("\\/");
                if (p != std::string::npos) k.configDir = img.substr(0, p);
            }
        }
        finishKernel(k);
        if (k.socksPort == 0) {
            const auto& launch = launches[k.pid];
            auto wanted = launch.mixedPort ? launch.mixedPort : launch.socksPort;
            k.discoveryError = "已发现内核，但 SOCKS/mixed 端口未监听";
            if (wanted) {
                k.discoveryError = "代理端口 " + std::to_string(wanted) + " 未就绪";
                for (const auto& [owner, port] : listeners) {
                    if (port != wanted || owner == k.pid) continue;
                    k.discoveryError = "代理端口 " + std::to_string(wanted) +
                        " 被其他进程占用（PID " + std::to_string(owner) + "）";
                    break;
                }
            }
        }
        kernels.push_back(std::move(k));
    }

    // Deterministic order for callers and tests.
    std::sort(kernels.begin(), kernels.end(),
              [](const DiscoveredKernel& a, const DiscoveredKernel& b) {
                  return lower(a.procName) < lower(b.procName);
              });

    return kernels;
}

// ---------------------------------------------------------------------------
// Fast-path helpers
// ---------------------------------------------------------------------------

DiscoveredKernel probePidPorts(uint32_t pid, const std::vector<uint16_t>& ports,
                               int timeoutMs) {
    const int t = clampProbeTimeout(timeoutMs);
    DiscoveredKernel k;
    k.pid = pid;
    k.procName = processNameOf(pid);
    k.cmdline = processCommandLine(pid);
    k.configDir = parseConfigDirFromCmdline(k.cmdline);
    for (uint16_t port : ports) {
        if (k.apiPort == 0) {
            bool needSecret = false;
            if (probeApiPort(port, t, &needSecret)) {
                k.apiPort = port;
                k.apiNeedSecret = needSecret;
                continue;  // API ports are not SOCKS ports
            }
        }
        if (k.socksPort == 0) {
            if (probeSocksPort(port, t)) k.socksPort = port;
        }
        if (k.apiPort != 0 && k.socksPort != 0) break;
    }
    if (k.socksPort == 0 && k.apiPort == 0) return {};  // nothing there
    finishKernel(k);
    return k;
}

std::vector<uint16_t> listeningPortsOf(uint32_t pid) {
    std::vector<uint16_t> out;
    for (const auto& [p, port] : enumerateListeners())
        if (p == pid) out.push_back(port);
    return out;
}

bool hasLoopbackListener(uint16_t port) {
    for (const auto& [pid, p] : enumerateListeners())
        if (p == port) return true;
    return false;
}

std::string processNameOf(uint32_t pid) {
    auto m = processNameMap();
    auto it = m.find(pid);
    return it != m.end() ? it->second : "";
}

std::vector<uint32_t> findProcessIdsByName(const std::vector<std::string>& tokens) {
    std::vector<uint32_t> out;
    for (const auto& [pid, name] : processNameMap()) {
        for (const auto& tok : tokens) {
            if (nameContains(name, tok)) {
                out.push_back(pid);
                break;
            }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// CFW secret
// ---------------------------------------------------------------------------

std::string readCfwSecret() {
    std::wstring path;
    {
        wchar_t buf[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return {};
        path = std::wstring(buf) + L"\\.config\\clash\\config.yaml";
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string line;
    while (std::getline(f, line)) {
        // Lines like: secret: abc-123
        size_t pos = line.find("secret:");
        if (pos == std::string::npos) continue;
        std::string v = line.substr(pos + 7);
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(0, 1);
        while (!v.empty() && (v.back() == '\r' || v.back() == '\n')) v.pop_back();
        if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'') {
            v = v.substr(1, v.size() - 2);
        }
        if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
            v = v.substr(1, v.size() - 2);
        }
        return v;
    }
    return {};
}

}  // namespace aps
