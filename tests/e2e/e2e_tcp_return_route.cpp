// Optional, manually built native regression. Never starts Engine and never
// opens its machine-wide filters. See native-probe-notes.txt before running.
// All traffic is an owned, exclusive-bound TCP tuple redirected to a local
// echo listener. An exact-tuple DROP handle follows our capture ahead of APS's
// normal priority 0; arbitrary third-party filter ordering is not controlled.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windivert.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "aps/nat_table.hpp"
#include "aps/packet_rewrite.hpp"

namespace {
using Clock = std::chrono::steady_clock;
constexpr int kSkip = 77;
constexpr uint32_t kTargetIp = 0xCB007111; // 203.0.113.17, TEST-NET-3
constexpr uint16_t kTargetPort = 443;
constexpr char kRequest[] = "aps-return-route-client-payload";
constexpr char kReply[] = "aps-return-route-server-payload";

struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { close(); }
    void close() {
        if (value != INVALID_SOCKET) {
            closesocket(value);
            value = INVALID_SOCKET;
        }
    }
};
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) WinDivertClose(value); }
};
struct WorkerResult { bool ok = false; std::string why; };
struct Counters {
    unsigned forward = 0, reverse = 0, syn = 0, synAck = 0;
    unsigned appFin = 0, relayFin = 0, rst = 0;
};

bool elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION info{};
    DWORD size = 0;
    const bool result = GetTokenInformation(token, TokenElevation, &info,
                                            sizeof(info), &size) && info.TokenIsElevated;
    CloseHandle(token);
    return result;
}

sockaddr_in endpoint(uint32_t ip, uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_addr.s_addr = htonl(ip);
    result.sin_port = htons(port);
    return result;
}
std::string ipText(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) +
           "." + std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
bool exclusiveBound(Socket& socket, uint32_t ip, uint16_t& port, bool listener) {
    socket.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket.value == INVALID_SOCKET) return false;
    BOOL exclusive = TRUE;
    if (setsockopt(socket.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive), sizeof(exclusive))) return false;
    auto address = endpoint(ip, 0); // OS chooses and reserves the port now.
    if (bind(socket.value, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return false;
    int length = sizeof(address);
    if (getsockname(socket.value, reinterpret_cast<sockaddr*>(&address), &length)) return false;
    port = ntohs(address.sin_port);
    if (!port || ntohl(address.sin_addr.s_addr) != ip) return false;
    if (listener && listen(socket.value, 1)) return false;
    u_long nonblocking = 1;
    return ioctlsocket(socket.value, FIONBIO, &nonblocking) == 0;
}
bool waitSocket(SOCKET socket, bool write, const std::atomic<bool>& stop,
                Clock::time_point deadline) {
    while (!stop.load() && Clock::now() < deadline) {
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(socket, &ready);
        timeval timeout{0, 20000};
        const int rc = select(0, write ? nullptr : &ready, write ? &ready : nullptr,
                              nullptr, &timeout);
        if (rc > 0) return true;
        if (rc < 0) return false;
    }
    return false;
}
bool sendAll(SOCKET socket, const char* text, size_t length,
             const std::atomic<bool>& stop, Clock::time_point deadline) {
    size_t sent = 0;
    while (sent < length && waitSocket(socket, true, stop, deadline)) {
        const int rc = send(socket, text + sent, static_cast<int>(length - sent), 0);
        if (rc > 0) sent += static_cast<size_t>(rc);
        else if (rc == 0 || WSAGetLastError() != WSAEWOULDBLOCK) return false;
    }
    return sent == length;
}
bool receiveToEof(SOCKET socket, std::string& text, const std::atomic<bool>& stop,
                  Clock::time_point deadline) {
    std::array<char, 256> data{};
    while (waitSocket(socket, false, stop, deadline)) {
        const int rc = recv(socket, data.data(), static_cast<int>(data.size()), 0);
        if (rc == 0) return true;
        if (rc < 0) { if (WSAGetLastError() == WSAEWOULDBLOCK) continue; return false; }
        text.append(data.data(), static_cast<size_t>(rc));
        if (text.size() > 1024) return false;
    }
    return false;
}

// The only selected packets are the reserved client tuple and the reserved
// local listener's return tuple. No wildcard port, process rule or DNS filter.
std::string exactFilter(uint32_t localIp, uint16_t clientPort, uint16_t relayPort,
                        bool includeReturn) {
    const auto local = ipText(localIp), target = ipText(kTargetIp);
    const std::string forward = "(ip.SrcAddr == " + local + " and ip.DstAddr == " + target +
        " and tcp.SrcPort == " + std::to_string(clientPort) + " and tcp.DstPort == " +
        std::to_string(kTargetPort) + ")";
    const std::string reverse = "(ip.SrcAddr == " + local + " and ip.DstAddr == " + local +
        " and tcp.SrcPort == " + std::to_string(relayPort) + " and tcp.DstPort == " +
        std::to_string(clientPort) + ")";
    return "outbound and ip and tcp and (" + forward +
           (includeReturn ? " or " + reverse : "") + ")";
}
bool filterMatches(const std::string& filter, uint32_t src, uint16_t sp,
                    uint32_t dst, uint16_t dp, bool outbound) {
    std::array<uint8_t, 64> packet{};
    const auto size = aps::pkt::buildRst(src, sp, dst, dp, 1, true, 1,
                                        packet.data(), packet.size());
    WINDIVERT_ADDRESS address{};
    address.Layer = WINDIVERT_LAYER_NETWORK;
    address.Event = WINDIVERT_EVENT_NETWORK_PACKET;
    address.Outbound = outbound;
    return WinDivertHelperEvalFilter(filter.c_str(), packet.data(),
                                     static_cast<UINT>(size), &address) != FALSE;
}
bool validateFilter(const std::string& filter, uint32_t localIp, uint16_t cp,
                     uint16_t rp, bool returns) {
    const char* error = nullptr;
    UINT position = 0;
    if (!WinDivertHelperCompileFilter(filter.c_str(), WINDIVERT_LAYER_NETWORK,
                                      nullptr, 0, &error, &position)) return false;
    const auto otherCp = static_cast<uint16_t>(cp == 65535 ? cp - 1 : cp + 1);
    const auto otherRp = static_cast<uint16_t>(rp == 65535 ? rp - 1 : rp + 1);
    return filterMatches(filter, localIp, cp, kTargetIp, kTargetPort, true) &&
        filterMatches(filter, localIp, rp, localIp, cp, true) == returns &&
        !filterMatches(filter, localIp, otherCp, kTargetIp, kTargetPort, true) &&
        !filterMatches(filter, localIp, cp, kTargetIp + 1, kTargetPort, true) &&
        !filterMatches(filter, localIp, cp, kTargetIp, kTargetPort + 1, true) &&
        !filterMatches(filter, localIp + 1, cp, kTargetIp, kTargetPort, true) &&
        !filterMatches(filter, localIp, cp, kTargetIp, kTargetPort, false) &&
        !filterMatches(filter, localIp, otherRp, localIp, cp, true) &&
        !filterMatches(filter, localIp, rp, localIp, otherCp, true) &&
        !filterMatches(filter, localIp, rp, localIp + 1, cp, true) &&
        !filterMatches(filter, kTargetIp, kTargetPort, localIp, cp, false);
}

int checkFilterBoundary() {
    // Pure user-mode helper calls only: no WSAStartup, route lookup, socket,
    // driver open, network packet injection, configuration or process changes.
    struct Case { uint32_t ip; uint16_t client, relay; };
    constexpr Case cases[] = {
        {0xC0000209, 50001, 50002}, // documentation-only sample address
        {0xC6336409, 65535, 49152},
        {0xCB007109, 49152, 65535}
    };
    for (const auto& item : cases) {
        const auto capture = exactFilter(item.ip, item.client, item.relay, true);
        const auto guard = exactFilter(item.ip, item.client, item.relay, false);
        if (!validateFilter(capture, item.ip, item.client, item.relay, true) ||
            !validateFilter(guard, item.ip, item.client, item.relay, false)) {
            std::puts("FAIL: pure filter-boundary check");
            return 1;
        }
    }
    std::puts("PASS: pure filter-boundary check; 3 static tuples, capture/guard predicates; no sockets/driver");
    return 0;
}

int run() {
    if (!elevated()) { std::puts("SKIP: requires elevation; no driver handle opened"); return kSkip; }
    // Route lookup is local kernel state; it sends no packet to TEST-NET.
    SOCKADDR_INET target{}, source{};
    target.Ipv4 = endpoint(kTargetIp, kTargetPort);
    MIB_IPFORWARD_ROW2 route{};
    if (GetBestRoute2(nullptr, 0, nullptr, &target, 0, &route, &source) != NO_ERROR ||
        source.si_family != AF_INET) {
        std::puts("SKIP: no IPv4 source/interface for TEST-NET route"); return kSkip;
    }
    const uint32_t localIp = ntohl(source.Ipv4.sin_addr.s_addr);
    if (!localIp || (localIp >> 24) == 127 || localIp == kTargetIp || !route.InterfaceIndex) {
        std::puts("SKIP: cannot establish an external original route"); return kSkip;
    }
    // Declaration order also preserves the escape guard during exceptional
    // cleanup: socket destructors run before the capture and guard handles.
    Handle guard, divert;
    Socket client, listener;
    uint16_t clientPort = 0, relayPort = 0;
    if (!exclusiveBound(client, localIp, clientPort, false) ||
        !exclusiveBound(listener, localIp, relayPort, true) || clientPort == relayPort) {
        std::puts("SKIP: cannot reserve distinct exclusive test sockets"); return kSkip;
    }
    const auto filter = exactFilter(localIp, clientPort, relayPort, true);
    const auto guardFilter = exactFilter(localIp, clientPort, relayPort, false);
    if (!validateFilter(filter, localIp, clientPort, relayPort, true) ||
        !validateFilter(guardFilter, localIp, clientPort, relayPort, false)) {
        std::puts("SKIP: narrow filter boundary checks failed"); return kSkip;
    }
    std::printf("owned pid=%lu local=%s client=%u relay=%u interface=%lu\nfilter=%s\n",
                GetCurrentProcessId(), ipText(localIp).c_str(), clientPort, relayPort,
                route.InterfaceIndex, filter.c_str());
    // Guard opens first and closes last, immediately after our priority 30000
    // capture and before APS's normal priority 0. It drops only the owned
    // TEST-NET tuple if our capture fails. Arbitrary third-party filters at
    // higher/equal priorities may transform tuples; this fixture cannot prove
    // containment against such filters and is not an isolation boundary.
    guard.value = WinDivertOpen(guardFilter.c_str(), WINDIVERT_LAYER_NETWORK,
                                29999, WINDIVERT_FLAG_DROP);
    if (guard.value == INVALID_HANDLE_VALUE) {
        std::printf("SKIP: exact-tuple escape guard unavailable: %lu\n", GetLastError()); return kSkip;
    }
    divert.value = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 30000, 0);
    if (divert.value == INVALID_HANDLE_VALUE) {
        std::printf("SKIP: narrow interception unavailable: %lu\n", GetLastError()); return kSkip;
    }
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) { std::puts("SKIP: receive event unavailable"); return kSkip; }
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    std::atomic<bool> stop{false}, clientDone{false}, serverDone{false};
    WorkerResult clientResult, serverResult;
    std::jthread serverWorker([&] {
        Socket peer;
        sockaddr_in address{};
        int length = sizeof(address);
        if (!waitSocket(listener.value, false, stop, deadline)) serverResult.why = "accept timeout";
        else peer.value = accept(listener.value, reinterpret_cast<sockaddr*>(&address), &length);
        if (peer.value != INVALID_SOCKET) {
            u_long nb = 1;
            if (ntohl(address.sin_addr.s_addr) != localIp || ntohs(address.sin_port) != clientPort ||
                ioctlsocket(peer.value, FIONBIO, &nb)) serverResult.why = "unexpected peer or mode";
            else {
                std::string request;
                serverResult.ok = receiveToEof(peer.value, request, stop, deadline) && request == kRequest &&
                    sendAll(peer.value, kReply, sizeof(kReply) - 1, stop, deadline) &&
                    shutdown(peer.value, SD_SEND) == 0;
                if (!serverResult.ok) serverResult.why = "request/EOF/reply mismatch";
            }
        } else if (serverResult.why.empty()) serverResult.why = "accept failed";
        peer.close();
        serverDone.store(true);
    });
    std::jthread clientWorker([&] {
        auto destination = endpoint(kTargetIp, kTargetPort);
        int rc = connect(client.value, reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
        bool connected = rc == 0;
        if (!connected && WSAGetLastError() == WSAEWOULDBLOCK &&
            waitSocket(client.value, true, stop, deadline)) {
            int error = 0, length = sizeof(error);
            connected = getsockopt(client.value, SOL_SOCKET, SO_ERROR,
                                   reinterpret_cast<char*>(&error), &length) == 0 && error == 0;
        }
        std::string reply;
        clientResult.ok = connected && sendAll(client.value, kRequest, sizeof(kRequest) - 1, stop, deadline) &&
            shutdown(client.value, SD_SEND) == 0 && receiveToEof(client.value, reply, stop, deadline) &&
            reply == kReply;
        if (!clientResult.ok) clientResult.why = connected ? "payload/EOF mismatch" : "connect timeout/failure";
        clientDone.store(true);
    });
    Counters counts;
    aps::NatEntry entry;
    bool sawSyn = false, pumpOk = true, nonExternal = false;
    auto drainUntil = deadline;
    std::vector<uint8_t> packet(65535);
    while (pumpOk && Clock::now() < deadline) {
        WINDIVERT_ADDRESS address{};
        UINT addressLength = sizeof(address), received = 0;
        OVERLAPPED pending{};
        pending.hEvent = event;
        ResetEvent(event);
        const BOOL immediate = WinDivertRecvEx(divert.value, packet.data(),
            static_cast<UINT>(packet.size()), &received, 0, &address, &addressLength, &pending);
        if (!immediate && GetLastError() != ERROR_IO_PENDING) { pumpOk = false; break; }
        bool cancel = false;
        if (!immediate) {
            for (;;) {
                if (clientDone.load() && serverDone.load() && drainUntil == deadline)
                    drainUntil = Clock::now() + std::chrono::milliseconds(250);
                if (Clock::now() >= deadline || Clock::now() >= drainUntil) { cancel = true; break; }
                const DWORD wait = WaitForSingleObject(event, 25);
                if (wait == WAIT_OBJECT_0) break;
                if (wait != WAIT_TIMEOUT) { cancel = true; pumpOk = false; break; }
            }
            if (cancel) CancelIoEx(divert.value, &pending);
            DWORD completed = 0;
            const BOOL ok = GetOverlappedResult(divert.value, &pending, &completed, TRUE);
            if (cancel) break;
            if (!ok) { pumpOk = false; break; }
            received = completed;
        }
        aps::pkt::TcpPacket view;
        if (!aps::pkt::parseTcpPacket(packet.data(), received, view)) { pumpOk = false; break; }
        if (view.srcIp == localIp && view.srcPort == clientPort &&
            view.dstIp == kTargetIp && view.dstPort == kTargetPort) {
            if (!sawSyn) {
                if (!view.syn || view.ackFlag || address.Loopback || !address.Outbound ||
                    !address.Network.IfIdx) {
                    nonExternal = address.Loopback != 0; pumpOk = false; break;
                }
                entry.appPacketMeta = {address.Outbound != 0, address.Loopback != 0,
                    address.Impostor != 0, address.IPv6 != 0,
                    address.Network.IfIdx, address.Network.SubIfIdx};
                sawSyn = true;
            }
            ++counts.forward;
            if (view.syn) ++counts.syn;
            if (view.fin) ++counts.appFin;
            if (view.rst) ++counts.rst;
            aps::pkt::rewriteDst(view, localIp, relayPort);
            address.Outbound = 1; // native local listener delivery
        } else if (view.srcIp == localIp && view.srcPort == relayPort &&
                   view.dstIp == localIp && view.dstPort == clientPort && sawSyn) {
            ++counts.reverse;
            if (view.syn && view.ackFlag) ++counts.synAck;
            if (view.fin) ++counts.relayFin;
            if (view.rst) ++counts.rst;
            aps::pkt::rewriteSrc(view, kTargetIp, kTargetPort);
            const auto metadata = entry.returnPacketMeta(); // production decision under test
            address.Outbound = metadata.outbound;
            address.Loopback = metadata.loopback;
            address.Impostor = metadata.impostor;
            address.Network.IfIdx = metadata.ifIdx;
            address.Network.SubIfIdx = metadata.subIfIdx;
        } else { pumpOk = false; break; } // never broaden a mismatched tuple
        if (!WinDivertHelperCalcChecksums(packet.data(), received, &address, 0) ||
            !WinDivertSend(divert.value, packet.data(), received, nullptr, &address)) {
            std::printf("packet reinjection failed: %lu\n", GetLastError()); pumpOk = false;
        }
    }
    stop.store(true);
    clientWorker.join();
    serverWorker.join();
    // Only our sockets/handles are closed. Guard remains active while socket
    // teardown occurs and the capture handle is closed by the RAII destructor.
    client.close(); listener.close();
    CloseHandle(event);
    std::printf("syn=%u synack=%u forward=%u reverse=%u app_fin=%u relay_fin=%u rst=%u\n",
                counts.syn, counts.synAck, counts.forward, counts.reverse,
                counts.appFin, counts.relayFin, counts.rst);
    const bool pass = pumpOk && sawSyn && !entry.returnPacketMeta().outbound &&
        clientResult.ok && serverResult.ok && counts.syn && counts.synAck &&
        counts.appFin && counts.relayFin && !counts.rst;
    if (nonExternal) { std::puts("SKIP: original SYN was loopback; external-route case not exercised"); return kSkip; }
    std::printf("%s: explicit inbound return; client=%s server=%s\n",
                pass ? "PASS" : "FAIL", clientResult.ok ? "OK" : clientResult.why.c_str(),
                serverResult.ok ? "OK" : serverResult.why.c_str());
    return pass ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && !std::strcmp(argv[1], "--check-filter-boundary"))
        return checkFilterBoundary();
    if (argc != 2 || std::strcmp(argv[1], "--run-owned-tuple")) {
        std::puts("SKIP: use --check-filter-boundary (pure) or --run-owned-tuple (admin); no socket/driver operation performed");
        return kSkip;
    }
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return kSkip;
    const int result = run();
    WSACleanup();
    return result;
}
