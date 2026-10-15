#include "aps/relay_server.hpp"

#include "aps/log.hpp"
#include "aps/path_util.hpp"

namespace aps {

bool RelayServer::start(const RelayParams& params, uint16_t listenPort, Resolver resolver,
                        std::string* err) {
    params_ = params;
    resolver_ = std::move(resolver);

    listener_ = net::makeTcpSocket();
    if (listener_ == INVALID_SOCKET) {
        if (err) *err = "relay socket() failed: " + net::lastError();
        return false;
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.S_un.S_addr = htonl(0);  // INADDR_ANY: reachable via 127.0.0.1
                                         // AND via the machine's own LAN IP,
                                         // which is what the NAT rewrite uses
    sa.sin_port = htons(listenPort);
    if (bind(listener_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
        if (err) *err = "relay bind failed on 127.0.0.1:" + std::to_string(listenPort) +
                        ": " + net::lastError();
        net::closeSocket(listener_);
        return false;
    }
    if (listen(listener_, SOMAXCONN) == SOCKET_ERROR) {
        if (err) *err = "relay listen failed: " + net::lastError();
        net::closeSocket(listener_);
        return false;
    }
    sockaddr_in actual{};
    int len = sizeof(actual);
    getsockname(listener_, reinterpret_cast<sockaddr*>(&actual), &len);
    listenPort_.store(ntohs(actual.sin_port));

    stopping_.store(false);
    acceptThread_ = std::thread([this] { acceptLoop(); });
    return true;
}

void RelayServer::stop() {
    if (listener_ == INVALID_SOCKET) return;
    stopping_.store(true);
    shutdown(listener_, SD_BOTH);
    closesocket(listener_);
    if (acceptThread_.joinable()) acceptThread_.join();
    listener_ = INVALID_SOCKET; // acceptLoop no longer reads this member
    listenPort_.store(0);

    // Claim all remaining thread objects under the same lock used by the
    // self-reaper. Removed workers can no longer detach themselves. Wake all
    // sessions before joining so one slow close does not postpone the others.
    std::map<uint64_t, std::shared_ptr<RelayEntry>> toAbort;
    {
        std::lock_guard<std::mutex> lk(sessionsMu_);
        toAbort.swap(sessions_);
    }
    for (auto& [id, entry] : toAbort) entry->session->abort();
    for (auto& [id, entry] : toAbort) {
        if (entry->thread.joinable()) entry->thread.join();
    }
}

size_t RelayServer::activeSessions() const {
    std::lock_guard<std::mutex> lk(const_cast<RelayServer*>(this)->sessionsMu_);
    return sessions_.size();
}

void RelayServer::abortByPeer(uint32_t appIp, uint16_t appPort) {
    std::vector<std::shared_ptr<RelaySession>> hits;
    {
        std::lock_guard<std::mutex> lk(sessionsMu_);
        for (auto& kv : sessions_) {
            if (kv.second->session->appPeer().ip == appIp &&
                kv.second->session->appPeer().port == appPort) {
                hits.push_back(kv.second->session);
            }
        }
    }
    for (auto& s : hits) s->abort();
}

void RelayServer::updateParams(const RelayParams& params) {
    std::lock_guard<std::mutex> lk(sessionsMu_);
    params_ = params;
}

void RelayServer::reapSession(uint64_t id) {
    std::lock_guard<std::mutex> lk(sessionsMu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end()) return; // stop() owns this worker and will join
    // Thread publication, detach and removal share one lock. The worker's
    // capture keeps the entry alive until its function has returned.
    it->second->thread.detach();
    sessions_.erase(it);
}

void RelayServer::acceptLoop() {
    while (!stopping_.load()) {
        sockaddr_in peer{};
        int peerLen = sizeof(peer);
        SOCKET app = accept(listener_, reinterpret_cast<sockaddr*>(&peer), &peerLen);
        if (app == INVALID_SOCKET) {
            int e = WSAGetLastError();
            if (stopping_.load()) break;
            if (e == WSAENOTSOCK || e == WSAEINVAL) break;
            log::wf("relay accept failed: {}", net::wsaErrorMessage(e));
            Sleep(50);
            continue;
        }
        counters.accepted.fetch_add(1);
        net::Endpoint4 appPeer{ntohl(peer.sin_addr.S_un.S_addr),
                               static_cast<uint16_t>(ntohs(peer.sin_port))};

        // Reverse-NAT lookup: unknown peers must never be tunneled (otherwise
        // this listener would be an open proxy).
        std::optional<RelayTarget> target = resolver_
            ? resolver_(appPeer.ip, appPeer.port)
            : std::nullopt;
        if (!target) {
            counters.unresolved.fetch_add(1);
            net::enableAbortiveClose(app);
            net::closeSocket(app);
            log::wf("relay: no NAT entry for {}:{}, closed",
                    aps::formatIpv4(appPeer.ip), appPeer.port);
            continue;
        }
        {
            std::lock_guard<std::mutex> lk(sessionsMu_);
            if (sessions_.size() >= params_.maxSessions) {
                net::enableAbortiveClose(app);
                net::closeSocket(app);
                log::wf("relay: session cap ({}) reached, closing new connection",
                        params_.maxSessions);
                continue;
            }

            uint64_t id = nextSessionId_++;
            auto entry = std::make_shared<RelayEntry>();
            // Copy endpoint, credentials and timeouts as one config snapshot.
            entry->session = std::make_shared<RelaySession>(id, app, appPeer,
                                                            std::move(*target), params_);
            sessions_.emplace(id, entry);
            // A fast EOF/failure may finish before the constructor returns.
            // Keep the lock until its std::thread has been published.
            entry->thread = std::thread([this, entry]() {
                RelaySession& s = *entry->session;
                s.run([this](RelaySession& done) {
                    if (done.ok()) {
                        counters.completed.fetch_add(1);
                    } else if (done.failureKind() == RelayFailureKind::Aborted) {
                        counters.aborted.fetch_add(1);
                    } else {
                        counters.socksFail.fetch_add(1);
                    }
                    // Engine's real-traffic failure signal (the relay thread
                    // reports; the node monitor consumes). Never block here:
                    // the callback only touches small mutex-guarded state.
                    const RelayTarget& t = done.target();
                    if (t.onResult) {
                        t.onResult(t.outletId, t.origDst.ip, t.origDst.port,
                                   done.ok(), done.failureKind(), done.error());
                    }
                });
                reapSession(s.id());
            });
        }
    }
}

}  // namespace aps
