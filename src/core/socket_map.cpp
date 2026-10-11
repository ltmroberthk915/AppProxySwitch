#include "aps/socket_map.hpp"

#include <windows.h>

#include <iterator>

#include "aps/log.hpp"
#include "aps/time_util.hpp"

namespace aps {

std::wstring SocketMap::defaultPathResolver(uint32_t pid) {
    if (pid == 0 || pid == 4) return {};  // kernel/system: no user image path
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buf));
    std::wstring path;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) {
        path.assign(buf, size);
    }
    CloseHandle(h);
    return path;
}

void SocketMap::setPathResolver(PathResolver r) {
    std::lock_guard<std::mutex> lk(resolverMu_);
    resolver_ = std::move(r);
}

std::wstring SocketMap::resolvePathCached(uint32_t pid) { return resolvePath(pid); }

std::wstring SocketMap::resolvePath(uint32_t pid) {
    int64_t now = nowMs();
    {
        std::lock_guard<std::mutex> lk(resolverMu_);
        auto it = pidCache_.find(pid);
        if (it != pidCache_.end() && now - it->second.second < 30000) {
            return it->second.first;
        }
    }
    PathResolver r;
    {
        std::lock_guard<std::mutex> lk(resolverMu_);
        r = resolver_;
    }
    if (!r) r = &defaultPathResolver;
    std::wstring path = r(pid);
    if (path.empty()) return {};
    std::lock_guard<std::mutex> lk(resolverMu_);
    if (pidCache_.size() > 4096) pidCache_.clear();
    pidCache_[pid] = {path, now};
    return path;
}

void SocketMap::onConnect(uint32_t localIp, uint16_t localPort, uint32_t remoteIp,
                          uint16_t remotePort, uint32_t pid, uint8_t protocol) {
    Entry e;
    e.pid = pid;
    e.remoteIp = remoteIp;
    e.remotePort = remotePort;
    e.protocol = protocol;
    e.lastSeenMs = nowMs();
    e.path = resolvePath(pid);
    std::unique_lock<std::shared_mutex> lk(mu_);
    map_[Key{localIp, localPort}] = std::move(e);
}

void SocketMap::onClose(uint32_t localIp, uint16_t localPort) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    map_.erase(Key{localIp, localPort});
}

std::optional<SocketMap::Entry> SocketMap::find(uint32_t localIp, uint16_t localPort) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = map_.find(Key{localIp, localPort});
    if (it == map_.end()) return std::nullopt;
    return it->second;
}

void SocketMap::insertResolved(uint32_t localIp, uint16_t localPort, uint32_t remoteIp,
                               uint16_t remotePort, uint32_t pid, const std::wstring& path,
                               uint8_t protocol) {
    Entry e;
    e.pid = pid;
    e.remoteIp = remoteIp;
    e.remotePort = remotePort;
    e.protocol = protocol;
    e.lastSeenMs = nowMs();
    e.path = path;
    std::unique_lock<std::shared_mutex> lk(mu_);
    map_[Key{localIp, localPort}] = std::move(e);
}

size_t SocketMap::sweep(int64_t nowMs, int ttlMs) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    size_t before = map_.size();
    for (auto it = map_.begin(); it != map_.end();) {
        if (nowMs - it->second.lastSeenMs > ttlMs) {
            it = map_.erase(it);
        } else {
            ++it;
        }
    }
    return before - map_.size();
}

size_t SocketMap::size() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return map_.size();
}

}  // namespace aps
