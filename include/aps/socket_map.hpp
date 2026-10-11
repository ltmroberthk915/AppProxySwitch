// (local ip:port) -> owning process snapshot, fed by SOCKET-layer connect
// events (primary) and GetExtendedTcpTable (fallback). Entries freeze the
// process path at event time so later PID reuse cannot re-attribute a flow.
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace aps {

class SocketMap {
public:
    // Resolves a PID to its full executable path; injectable for tests.
    using PathResolver = std::function<std::wstring(uint32_t pid)>;

    struct Entry {
        uint32_t pid = 0;
        std::wstring path;        // frozen at event time
        uint32_t remoteIp = 0;    // host order
        uint16_t remotePort = 0;
        uint8_t protocol = 6;
        int64_t lastSeenMs = 0;
    };

    void setPathResolver(PathResolver r);

    // SOCEKT-layer CONNECT: store/overwrite the mapping for (local).
    void onConnect(uint32_t localIp, uint16_t localPort, uint32_t remoteIp,
                   uint16_t remotePort, uint32_t pid, uint8_t protocol);
    // SOCKET-layer CLOSE: drop the mapping.
    void onClose(uint32_t localIp, uint16_t localPort);

    std::optional<Entry> find(uint32_t localIp, uint16_t localPort) const;

    // Direct insertion of a resolved entry (TCP-table fallback path).
    void insertResolved(uint32_t localIp, uint16_t localPort, uint32_t remoteIp,
                        uint16_t remotePort, uint32_t pid, const std::wstring& path,
                        uint8_t protocol);

    // Cached PID -> path resolution using the configured resolver.
    std::wstring resolvePathCached(uint32_t pid);

    // Evict entries idle for longer than ttlMs. Returns number removed.
    size_t sweep(int64_t nowMs, int ttlMs);

    size_t size() const;

    static std::wstring defaultPathResolver(uint32_t pid);

private:
    std::wstring resolvePath(uint32_t pid);

    mutable std::shared_mutex mu_;
    struct Key {
        uint32_t ip;
        uint16_t port;
        bool operator==(const Key& o) const { return ip == o.ip && port == o.port; }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const {
            return std::hash<uint64_t>()((uint64_t)k.ip << 16 | k.port);
        }
    };
    std::unordered_map<Key, Entry, KeyHash> map_;
    std::mutex resolverMu_;
    PathResolver resolver_;
    std::unordered_map<uint32_t, std::pair<std::wstring, int64_t>> pidCache_;
};

}  // namespace aps
