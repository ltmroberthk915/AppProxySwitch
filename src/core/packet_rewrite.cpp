#include "aps/packet_rewrite.hpp"

#include <cstring>

namespace aps::pkt {

bool parseUdpPacket(const uint8_t* data, size_t len, PWINDIVERT_IPHDR& ip,
                    PWINDIVERT_UDPHDR& udp, uint32_t& srcIpHost, uint16_t& srcPortHost,
                    uint32_t& dstIpHost, uint16_t& dstPortHost) {
    UINT8 proto = 0;
    if (!WinDivertHelperParsePacket(data, static_cast<UINT>(len), &ip, nullptr, &proto,
                                    nullptr, nullptr, nullptr, &udp, nullptr, nullptr,
                                    nullptr, nullptr)) {
        return false;
    }
    if (ip == nullptr || udp == nullptr || proto != IPPROTO_UDP) return false;
    if (WINDIVERT_IPHDR_GET_FRAGOFF(ip) != 0) return false;
    srcIpHost = ntohl(ip->SrcAddr);
    dstIpHost = ntohl(ip->DstAddr);
    srcPortHost = ntohs(udp->SrcPort);
    dstPortHost = ntohs(udp->DstPort);
    return true;
}

bool parseTcpPacket(const uint8_t* data, size_t len, TcpPacket& out) {
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    UINT8 proto = 0;
    if (!WinDivertHelperParsePacket(data, static_cast<UINT>(len), &ip, nullptr, &proto,
                                    nullptr, nullptr, &tcp, nullptr, nullptr, nullptr,
                                    nullptr, nullptr)) {
        return false;
    }
    if (ip == nullptr || tcp == nullptr || proto != IPPROTO_TCP) return false;
    // Ignore fragments with an offset (they cannot be rewritten safely).
    if (WINDIVERT_IPHDR_GET_FRAGOFF(ip) != 0) return false;

    out.ip = ip;
    out.tcp = tcp;
    out.srcIp = ntohl(ip->SrcAddr);
    out.dstIp = ntohl(ip->DstAddr);
    out.srcPort = ntohs(tcp->SrcPort);
    out.dstPort = ntohs(tcp->DstPort);
    out.seq = ntohl(tcp->SeqNum);
    out.ack = ntohl(tcp->AckNum);
    out.syn = tcp->Syn != 0;
    out.ackFlag = tcp->Ack != 0;
    out.fin = tcp->Fin != 0;
    out.rst = tcp->Rst != 0;

    const uint8_t* ipStart = reinterpret_cast<const uint8_t*>(ip);
    size_t ipHdrLen = (ip->HdrLength & 0xF) * 4;
    size_t tcpHdrLen = ((tcp->HdrLength & 0xF) >> 0) * 4;
    // WinDivertHelperParsePacket gives us tcp == (ip payload start); payload
    // begins after the TCP header and runs to the IP total length.
    uint16_t totalLen = ntohs(ip->Length);
    size_t headersEnd = ipHdrLen + tcpHdrLen;
    if (headersEnd > totalLen || totalLen > len) return false;
    const uint8_t* tcpStart = ipStart + ipHdrLen;
    out.payload = tcpStart + tcpHdrLen;
    out.payloadLen = static_cast<uint32_t>(totalLen - headersEnd);
    return true;
}

static void putIpBytes(uint32_t hostOrder, uint8_t* out4) {
    out4[0] = static_cast<uint8_t>(hostOrder >> 24);
    out4[1] = static_cast<uint8_t>(hostOrder >> 16);
    out4[2] = static_cast<uint8_t>(hostOrder >> 8);
    out4[3] = static_cast<uint8_t>(hostOrder);
}

void rewriteDst(TcpPacket& p, uint32_t newDstIpHost, uint16_t newDstPortHost) {
    uint8_t b[4];
    putIpBytes(newDstIpHost, b);
    std::memcpy(&p.ip->DstAddr, b, 4);
    uint16_t netPort = htons(newDstPortHost);
    std::memcpy(&p.tcp->DstPort, &netPort, 2);
    p.dstIp = newDstIpHost;
    p.dstPort = newDstPortHost;
}

void rewriteSrc(TcpPacket& p, uint32_t newSrcIpHost, uint16_t newSrcPortHost) {
    uint8_t b[4];
    putIpBytes(newSrcIpHost, b);
    std::memcpy(&p.ip->SrcAddr, b, 4);
    uint16_t netPort = htons(newSrcPortHost);
    std::memcpy(&p.tcp->SrcPort, &netPort, 2);
    p.srcIp = newSrcIpHost;
    p.srcPort = newSrcPortHost;
}

void recalcChecksums(uint8_t* data, size_t len) {
    WinDivertHelperCalcChecksums(data, static_cast<UINT>(len), nullptr, 0);
}

uint32_t nextSeq(const TcpPacket& p) {
    uint32_t seq = p.seq + p.payloadLen;
    if (p.syn) ++seq;
    if (p.fin) ++seq;
    return seq;
}

size_t buildRst(uint32_t srcIpHost, uint16_t srcPortHost, uint32_t dstIpHost,
                uint16_t dstPortHost, uint32_t seqHost, bool withAck,
                uint32_t ackHost, uint8_t* out, size_t cap) {
    if (cap < 40) return 0;
    std::memset(out, 0, 40);
    // IPv4 header
    out[0] = 0x45;                       // v4, hl=5
    out[2] = 0; out[3] = 40;             // total length
    out[4] = 0; out[5] = 0;              // id
    out[6] = 0x40; out[7] = 0;           // DF
    out[8] = 64;                         // ttl
    out[9] = 6;                          // TCP
    // out[10..11] checksum = 0 (recalc later)
    putIpBytes(srcIpHost, out + 12);
    putIpBytes(dstIpHost, out + 16);
    // TCP header
    uint8_t* tcp = out + 20;
    uint16_t sp = htons(srcPortHost), dp = htons(dstPortHost);
    std::memcpy(tcp + 0, &sp, 2);
    std::memcpy(tcp + 2, &dp, 2);
    uint32_t seq = htonl(seqHost);
    std::memcpy(tcp + 4, &seq, 4);
    uint32_t ack = htonl(ackHost);
    std::memcpy(tcp + 8, &ack, 4);
    tcp[12] = 0x50;                      // data offset 5
    tcp[13] = 0x04 | (withAck ? 0x10 : 0);  // RST (+ACK)
    uint16_t win = htons(0);
    std::memcpy(tcp + 14, &win, 2);
    recalcChecksums(out, 40);
    return 40;
}

}  // namespace aps::pkt
