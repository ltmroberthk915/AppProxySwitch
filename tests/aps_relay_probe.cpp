// Manual, bounded transport diagnostic. No Engine, driver, configuration,
// credentials or application data capture. Listens only on an ephemeral
// loopback port and forwards every session to one caller-specified target.
#include <winsock2.h>
#include <windows.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "aps/log.hpp"
#include "aps/net.hpp"
#include "aps/relay_server.hpp"

int main(int argc, char** argv) {
    // proxy-port original-ip allowed-name-or-dash seconds log-directory
    if (argc != 6) return 2;
    const int proxyPort = std::atoi(argv[1]);
    const int seconds = std::atoi(argv[4]);
    IN_ADDR original{};
    if (proxyPort < 1 || proxyPort > 65535 || seconds < 1 || seconds > 600 ||
        InetPtonA(AF_INET, argv[2], &original) != 1) return 2;
    if (!aps::net::initWinsock()) return 3;
    const auto dir = std::filesystem::path(argv[5]).wstring();
    if (!aps::log::init(dir, aps::log::Level::Info, 2, 2, L"relay-probe")) return 4;
    SOCKET listener = aps::net::makeTcpSocket();
    auto sa = aps::net::toSockaddr({0x7F000001, 0});
    if (::bind(listener, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) ||
        ::listen(listener, 8)) return 5;
    int len = sizeof(sa);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&sa), &len)) return 5;
    std::mutex outputMu;
    std::cout << "{\"pid\":" << GetCurrentProcessId()
              << ",\"port\":" << ntohs(sa.sin_port) << "}" << std::endl;
    aps::RelayParams params;
    params.proxy = {0x7F000001, static_cast<uint16_t>(proxyPort)};
    params.connectTimeoutMs = 5000;
    params.pumpTimeoutMs = 10000;
    std::vector<std::shared_ptr<aps::RelaySession>> sessions;
    std::vector<std::thread> workers;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (sessions.size() < 16 && std::chrono::steady_clock::now() < deadline) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener, &readable);
        timeval tv{0, 200000};
        if (select(0, &readable, nullptr, nullptr, &tv) <= 0) continue;
        sockaddr_in peer{};
        int peerLen = sizeof(peer);
        SOCKET client = accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerLen);
        if (client == INVALID_SOCKET) continue;
        aps::RelayTarget target;
        target.origDst = {ntohl(original.S_un.S_addr), 443};
        target.origSource = {ntohl(peer.sin_addr.S_un.S_addr), ntohs(peer.sin_port)};
        target.outletId = "manual-probe";
        target.proxy = params.proxy;
        // Enable the production DNS-correlation path without manufacturing
        // a DNS association. A configured name can supplement this callback.
        target.allowTlsDomain = [](const std::string&) { return false; };
        if (std::string(argv[3]) != "-") target.tlsDomainAllowlist = {argv[3]};
        auto session = std::make_shared<aps::RelaySession>(sessions.size() + 1,
            client, target.origSource, std::move(target), params);
        sessions.push_back(session);
        workers.emplace_back([session, &outputMu] {
            session->run([&outputMu](aps::RelaySession& done) {
                std::lock_guard<std::mutex> lk(outputMu);
                std::cout << "{\"flow\":" << done.id() << ",\"tcp_completed\":"
                          << (done.ok() ? "true" : "false") << ",\"failure\":\""
                          << aps::relayFailureKindName(done.failureKind())
                          << "\",\"up\":" << done.bytesUp() << ",\"down\":"
                          << done.bytesDown() << "}" << std::endl;
            });
        });
    }
    aps::net::closeSocket(listener);
    for (auto& session : sessions) session->abort();
    for (auto& worker : workers) worker.join();
    aps::log::shutdown();
    aps::net::cleanupWinsock();
    return 0;
}
