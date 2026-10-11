// Scriptable in-memory IDivertDevice + raw packet builder for engine tests.
#pragma once

#ifndef APS_BUILD_TESTS
#error "test-only header"
#endif

#include <windivert.h>

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

#include "aps/divert_device.hpp"

namespace aps::test {

// ---- raw IPv4/TCP packet builder --------------------------------------------
inline std::vector<uint8_t> buildTcpPacket(uint32_t srcIpHost, uint16_t srcPortHost,
                                           uint32_t dstIpHost, uint16_t dstPortHost,
                                           uint32_t seq, uint32_t ack, uint8_t flags,
                                           const std::vector<uint8_t>& payload = {}) {
    size_t total = 20 + 20 + payload.size();
    std::vector<uint8_t> pkt(total, 0);
    auto* ip = reinterpret_cast<PWINDIVERT_IPHDR>(pkt.data());
    auto* tcp = reinterpret_cast<PWINDIVERT_TCPHDR>(pkt.data() + 20);

    uint32_t srcNet = htonl(srcIpHost), dstNet = htonl(dstIpHost);
    std::memcpy(&ip->SrcAddr, &srcNet, 4);
    std::memcpy(&ip->DstAddr, &dstNet, 4);
    ip->HdrLength = 5;
    ip->Version = 4;
    uint16_t lenNet = htons(static_cast<uint16_t>(total));
    std::memcpy(&ip->Length, &lenNet, 2);
    ip->TTL = 64;
    ip->Protocol = 6;

    uint16_t sp = htons(srcPortHost), dp = htons(dstPortHost);
    std::memcpy(&tcp->SrcPort, &sp, 2);
    std::memcpy(&tcp->DstPort, &dp, 2);
    uint32_t seqNet = htonl(seq), ackNet = htonl(ack);
    std::memcpy(&tcp->SeqNum, &seqNet, 4);
    std::memcpy(&tcp->AckNum, &ackNet, 4);
    tcp->HdrLength = 5;
    tcp->Syn = flags & 0x02 ? 1 : 0;
    tcp->Ack = flags & 0x10 ? 1 : 0;
    tcp->Fin = flags & 0x01 ? 1 : 0;
    tcp->Rst = flags & 0x04 ? 1 : 0;
    tcp->Psh = flags & 0x08 ? 1 : 0;
    tcp->Window = htons(64240);
    if (!payload.empty()) std::memcpy(pkt.data() + 40, payload.data(), payload.size());

    WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(total), nullptr, 0);
    return pkt;
}

// Minimal IPv6 TCP packet builder (happy-eyeballs blocking tests).
inline std::vector<uint8_t> buildTcp6Packet(uint16_t srcPortHost, uint16_t dstPortHost,
                                            uint8_t flags, uint32_t seq = 0) {
    size_t total = 40 + 20;
    std::vector<uint8_t> pkt(total, 0);
    auto* ip6 = reinterpret_cast<PWINDIVERT_IPV6HDR>(pkt.data());
    auto* tcp = reinterpret_cast<PWINDIVERT_TCPHDR>(pkt.data() + 40);
    ip6->Version = 6;
    ip6->NextHdr = 6;  // TCP
    ip6->HopLimit = 64;
    uint16_t plen = htons(20);
    std::memcpy(&ip6->Length, &plen, 2);
    uint32_t src[4] = {0x20010DB8, 0, 0, 1};  // 2001:db8::1
    uint32_t dst[4] = {0x20010DB8, 0, 0, 2};
    std::memcpy(ip6->SrcAddr, src, 16);
    std::memcpy(ip6->DstAddr, dst, 16);

    uint16_t sp = htons(srcPortHost), dp = htons(dstPortHost);
    std::memcpy(&tcp->SrcPort, &sp, 2);
    std::memcpy(&tcp->DstPort, &dp, 2);
    uint32_t seqNet = htonl(seq);
    std::memcpy(&tcp->SeqNum, &seqNet, 4);
    tcp->HdrLength = 5;
    tcp->Syn = flags & 0x02 ? 1 : 0;
    tcp->Ack = flags & 0x10 ? 1 : 0;
    tcp->Window = htons(64240);
    WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(total), nullptr, 0);
    return pkt;
}

// Minimal IPv4 UDP packet builder (UDP block / DHCP passthrough tests).
inline std::vector<uint8_t> buildUdpPacket(uint32_t srcIpHost, uint16_t srcPortHost,
                                           uint32_t dstIpHost, uint16_t dstPortHost,
                                           const std::vector<uint8_t>& payload = {}) {
    size_t total = 20 + 8 + payload.size();
    std::vector<uint8_t> pkt(total, 0);
    auto* ip = reinterpret_cast<PWINDIVERT_IPHDR>(pkt.data());
    auto* udp = reinterpret_cast<PWINDIVERT_UDPHDR>(pkt.data() + 20);

    uint32_t srcNet = htonl(srcIpHost), dstNet = htonl(dstIpHost);
    std::memcpy(&ip->SrcAddr, &srcNet, 4);
    std::memcpy(&ip->DstAddr, &dstNet, 4);
    ip->HdrLength = 5;
    ip->Version = 4;
    uint16_t lenNet = htons(static_cast<uint16_t>(total));
    std::memcpy(&ip->Length, &lenNet, 2);
    ip->TTL = 64;
    ip->Protocol = 17;

    uint16_t sp = htons(srcPortHost), dp = htons(dstPortHost);
    std::memcpy(&udp->SrcPort, &sp, 2);
    std::memcpy(&udp->DstPort, &dp, 2);
    uint16_t ulen = htons(static_cast<uint16_t>(8 + payload.size()));
    std::memcpy(&udp->Length, &ulen, 2);
    if (!payload.empty()) std::memcpy(pkt.data() + 28, payload.data(), payload.size());

    WinDivertHelperCalcChecksums(pkt.data(), static_cast<UINT>(total), nullptr, 0);
    return pkt;
}

// ---- fake device --------------------------------------------------------------
class FakeDivertDevice : public IDivertDevice {
public:
    struct Sent {
        std::vector<uint8_t> data;
        PacketMeta meta;
        bool synthetic = false;
    };

    bool start(uint16_t relayListenPort, bool blockUdp, bool blockIpv6Tcp,
               bool dnsFilter, std::string* err) override {
        (void)relayListenPort;
        (void)blockUdp;
        (void)blockIpv6Tcp;
        (void)dnsFilter;
        (void)err;
        started_ = true;
        return true;
    }

    void requestStop() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stopped_ = true;
        }
        cv_.notify_all();
    }

    void pushTcp(std::vector<uint8_t> pkt, PacketMeta meta = {true, false, false, false}) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            tcpIn_.push_back({std::move(pkt), meta});
        }
        cv_.notify_all();
    }
    void pushSocket(SocketEventInfo ev) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            socketIn_.push_back(std::move(ev));
        }
        cv_.notify_all();
    }
    void pushTcp6(std::vector<uint8_t> pkt) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            tcp6In_.push_back(std::move(pkt));
        }
        cv_.notify_all();
    }
    void pushUdp(std::vector<uint8_t> pkt, PacketMeta meta = {true, false, false, false}) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            udpIn_.push_back({std::move(pkt), meta});
        }
        cv_.notify_all();
    }
    void pushDns(std::vector<uint8_t> pkt, PacketMeta meta = {true, false, false, false}) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            dnsIn_.push_back({std::move(pkt), meta});
        }
        cv_.notify_all();
    }
    size_t sentDnsCount() {
        std::lock_guard<std::mutex> lk(mu_);
        return sentDns_.size();
    }
    std::vector<uint8_t> sentDns(size_t i) {
        std::lock_guard<std::mutex> lk(mu_);
        return sentDns_.at(i);
    }

    bool recvNetworkTcp(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        std::unique_lock<std::mutex> lk(mu_);
        while (!cv_.wait_for(lk, std::chrono::seconds(1),
                            [&] { return stopped_ || !tcpIn_.empty(); })) {
            tcpWaitTicks_.fetch_add(1);
        }
        if (stopped_ || tcpIn_.empty()) return false;
        auto [pkt, m] = std::move(tcpIn_.front());
        tcpIn_.pop_front();
        lastTcpMeta_ = m;
        meta = m;
        size_t n = pkt.size() < cap ? pkt.size() : cap;
        std::memcpy(buf, pkt.data(), n);
        len = n;
        return true;
    }

    uint64_t tcpReceiveWaitTicks() const override { return tcpWaitTicks_.load(); }

    bool recvNetworkUdp(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return stopped_ || !udpIn_.empty(); });
        if (stopped_ || udpIn_.empty()) return false;
        auto [pkt, m] = std::move(udpIn_.front());
        udpIn_.pop_front();
        lastUdpMeta_ = m;
        meta = m;
        size_t n = pkt.size() < cap ? pkt.size() : cap;
        std::memcpy(buf, pkt.data(), n);
        len = n;
        return true;
    }

    bool sendLastTcp(const uint8_t* buf, size_t len, bool forceLoopback) override {
        PacketMeta m = lastTcpMeta_;
        if (forceLoopback) m.loopback = true;
        std::lock_guard<std::mutex> lk(mu_);
        sent_.push_back(Sent{std::vector<uint8_t>(buf, buf + len), m, false});
        cvSent_.notify_all();
        return true;
    }
    bool sendLastUdp(const uint8_t* buf, size_t len) override {
        PacketMeta m = lastUdpMeta_;
        std::lock_guard<std::mutex> lk(mu_);
        sentUdp_.push_back({std::vector<uint8_t>(buf, buf + len), m, false});
        cvSent_.notify_all();
        return true;
    }
    bool sendLastTcp6(const uint8_t* buf, size_t len) override {
        PacketMeta m;
        m.outbound = true;
        m.ipv6 = true;
        std::lock_guard<std::mutex> lk(mu_);
        sentTcp6_.push_back(std::vector<uint8_t>(buf, buf + len));
        cvSent_.notify_all();
        return true;
    }
    bool recvNetworkTcp6(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return stopped_ || !tcp6In_.empty(); });
        if (stopped_ || tcp6In_.empty()) return false;
        auto pkt = std::move(tcp6In_.front());
        tcp6In_.pop_front();
        size_t n = pkt.size() < cap ? pkt.size() : cap;
        std::memcpy(buf, pkt.data(), n);
        len = n;
        meta.outbound = true;
        meta.ipv6 = true;
        return true;
    }
    bool recvNetworkDns(uint8_t* buf, size_t cap, size_t& len, PacketMeta& meta) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return stopped_ || !dnsIn_.empty(); });
        if (stopped_ || dnsIn_.empty()) return false;
        auto [pkt, m] = std::move(dnsIn_.front());
        dnsIn_.pop_front();
        size_t n = pkt.size() < cap ? pkt.size() : cap;
        std::memcpy(buf, pkt.data(), n);
        len = n;
        meta = m;
        return true;
    }
    bool sendLastDns(const uint8_t* buf, size_t len) override {
        std::lock_guard<std::mutex> lk(mu_);
        sentDns_.push_back(std::vector<uint8_t>(buf, buf + len));
        cvSent_.notify_all();
        return true;
    }
    bool sendDnsPacket(const uint8_t* buf, size_t len, const PacketMeta& meta) override {
        (void)meta;
        return sendLastDns(buf, len);
    }
    bool sendSyntheticTcp(const uint8_t* buf, size_t len, bool loopback) override {
        PacketMeta m;
        m.outbound = true;
        m.loopback = loopback;
        std::lock_guard<std::mutex> lk(mu_);
        sent_.push_back(Sent{std::vector<uint8_t>(buf, buf + len), m, true});
        cvSent_.notify_all();
        return true;
    }

    bool recvSocket(SocketEventInfo& ev) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return stopped_ || !socketIn_.empty(); });
        if (stopped_ || socketIn_.empty()) return false;
        ev = std::move(socketIn_.front());
        socketIn_.pop_front();
        return true;
    }

    // ---- assertions helper ----------------------------------------------------
    std::vector<Sent> sent() {
        std::lock_guard<std::mutex> lk(mu_);
        return sent_;
    }
    std::vector<Sent> sentUdp() {
        std::lock_guard<std::mutex> lk(mu_);
        return sentUdp_;
    }
    size_t sentUdpCount() {
        std::lock_guard<std::mutex> lk(mu_);
        return sentUdp_.size();
    }
    size_t sentTcp6Count() {
        std::lock_guard<std::mutex> lk(mu_);
        return sentTcp6_.size();
    }
    void clearSent() {
        std::lock_guard<std::mutex> lk(mu_);
        sent_.clear();
    }
    bool waitSent(size_t count, int timeoutMs) {
        std::unique_lock<std::mutex> lk(mu_);
        return cvSent_.wait_for(lk, std::chrono::milliseconds(timeoutMs),
                                [&] { return sent_.size() >= count; });
    }

private:
    std::mutex mu_;
    std::condition_variable cv_, cvSent_;
    bool started_ = false;
    bool stopped_ = false;
    std::atomic<uint64_t> tcpWaitTicks_{0};
    PacketMeta lastTcpMeta_{};
    PacketMeta lastUdpMeta_{};
    std::deque<std::pair<std::vector<uint8_t>, PacketMeta>> tcpIn_;
    std::deque<std::pair<std::vector<uint8_t>, PacketMeta>> udpIn_;
    std::deque<SocketEventInfo> socketIn_;
    std::deque<std::vector<uint8_t>> tcp6In_;
    std::deque<std::pair<std::vector<uint8_t>, PacketMeta>> dnsIn_;
    std::vector<Sent> sent_;
    std::vector<Sent> sentUdp_;
    std::vector<std::vector<uint8_t>> sentTcp6_;
    std::vector<std::vector<uint8_t>> sentDns_;
};

}  // namespace aps::test
