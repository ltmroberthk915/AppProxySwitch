#include "aps/dns_rewrite.hpp"

#include <cstring>
#include <algorithm>
#include <set>

namespace aps::dns {

namespace {

bool readName(const uint8_t* pkt, size_t len, size_t& pos, std::string& out) {
    out.clear();
    // No compression handling in QUERIES (they almost never use pointers);
    // enforce plain labels for safety.
    while (true) {
        if (pos >= len) return false;
        uint8_t b = pkt[pos];
        if (b == 0) {
            ++pos;
            if (out.empty()) return false;
            if (out.back() == '.') out.pop_back();
            return true;
        }
        if ((b & 0xC0) == 0xC0) {
            // Compression pointer — queries with pointers are exotic; accept
            // only a pointer to offset 12 (the classic root question form).
            if (pos + 1 >= len) return false;
            uint16_t target = static_cast<uint16_t>(((b & 0x3F) << 8) | pkt[pos + 1]);
            // Only the classic question-name pointer is needed here, and it
            // must point backward. Reject a self-pointer at offset 12 instead
            // of recursing forever on a malformed local query.
            if (target != 12 || target >= pos) return false;
            pos += 2;
            size_t sub = target;
            std::string tail;
            if (!readName(pkt, len, sub, tail)) return false;
            out += tail;
            if (out.back() == '.') out.pop_back();
            return true;
        }
        if (b > 63 || pos + 1 + b > len) return false;
        for (size_t i = 1; i <= b; ++i) {
            char c = static_cast<char>(pkt[pos + i]);
            // Keep it to hostname-safe characters.
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
                !(c >= '0' && c <= '9') && c != '-' && c != '_') {
                return false;
            }
            out.push_back(c);
        }
        out.push_back('.');
        pos += 1 + b;
    }
}

void writeName(const std::string& name, uint8_t* out, size_t& pos) {
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        std::string label =
            name.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
        out[pos++] = static_cast<uint8_t>(label.size());
        std::memcpy(out + pos, label.data(), label.size());
        pos += label.size();
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out[pos++] = 0;
}

}  // namespace

std::optional<Query> parseQuery(const uint8_t* pkt, size_t len) {
    // DNS header + at least one byte of question.
    if (!pkt || len < 17) return std::nullopt;
    Query q;
    q.id = static_cast<uint16_t>((pkt[0] << 8) | pkt[1]);
    uint16_t flags = static_cast<uint16_t>((pkt[2] << 8) | pkt[3]);
    uint16_t qd = static_cast<uint16_t>((pkt[4] << 8) | pkt[5]);
    uint16_t an = static_cast<uint16_t>((pkt[6] << 8) | pkt[7]);
    // Only plain standard queries (no response, no opcode games).
    if ((flags & 0x8000) != 0) return std::nullopt;  // QR set: it's a reply
    if ((flags & 0x7800) != 0) return std::nullopt;  // non-zero opcode
    if (qd != 1 || an != 0) return std::nullopt;     // single question only

    size_t pos = 12;
    std::string name;
    if (!readName(pkt, len, pos, name)) return std::nullopt;
    if (pos + 4 > len) return std::nullopt;
    uint16_t qtype = static_cast<uint16_t>((pkt[pos] << 8) | pkt[pos + 1]);
    uint16_t qclass = static_cast<uint16_t>((pkt[pos + 2] << 8) | pkt[pos + 3]);
    if (qclass != 1) return std::nullopt;             // IN only
    q.type = qtype;
    q.recursionDesired = (flags & 0x0100) != 0;
    q.name = std::move(name);
    return q;
}

std::optional<AQuery> parseAQuery(const uint8_t* pkt, size_t len) {
    auto q = parseQuery(pkt, len);
    if (!q || q->type != 1) return std::nullopt;
    return AQuery{q->id, std::move(q->name)};
}

size_t buildAResponse(const AQuery& q, const std::vector<uint32_t>& ipsHost,
                      uint8_t* out, size_t cap) {
    size_t questionLen = 1;  // root label
    {
        size_t start = 0;
        while (start <= q.name.size()) {
            size_t dot = q.name.find('.', start);
            size_t labelLen = dot == std::string::npos
                                  ? q.name.size() - start
                                  : dot - start;
            questionLen += 1 + labelLen;
            if (dot == std::string::npos) break;
            start = dot + 1;
        }
    }
    questionLen += 4;  // qtype + qclass
    size_t answerLen = ipsHost.size() * 16;  // name ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)+ip(4)
    size_t total = 12 + questionLen + answerLen;
    if (total > cap || ipsHost.empty()) return 0;

    std::memset(out, 0, total);
    // Header
    out[0] = static_cast<uint8_t>(q.id >> 8);
    out[1] = static_cast<uint8_t>(q.id & 0xFF);
    out[2] = 0x81;  // QR + RD + RA
    out[3] = 0x80;
    out[4] = 0; out[5] = 1;                      // QDCOUNT=1
    out[6] = 0; out[7] = static_cast<uint8_t>(ipsHost.size());  // ANCOUNT
    // out[8..11] NS/AR counts stay zero.

    // Question (mirrors the query).
    size_t pos = 12;
    writeName(q.name, out, pos);
    out[pos++] = 0; out[pos++] = 1;   // A
    out[pos++] = 0; out[pos++] = 1;   // IN

    // Answers: compression pointer to the question name (offset 12).
    for (uint32_t ip : ipsHost) {
        out[pos++] = 0xC0;
        out[pos++] = 0x0C;
        out[pos++] = 0; out[pos++] = 1;        // type A
        out[pos++] = 0; out[pos++] = 1;        // class IN
        out[pos++] = 0; out[pos++] = 0;        // TTL
        out[pos++] = 0; out[pos++] = 60;
        out[pos++] = 0; out[pos++] = 4;        // rdlength
        out[pos++] = static_cast<uint8_t>(ip >> 24);
        out[pos++] = static_cast<uint8_t>(ip >> 16);
        out[pos++] = static_cast<uint8_t>(ip >> 8);
        out[pos++] = static_cast<uint8_t>(ip);
    }
    return total;
}

size_t buildNoDataResponse(const Query& q, uint8_t* out, size_t cap) {
    size_t questionLen = 1;  // root label
    size_t start = 0;
    while (start <= q.name.size()) {
        size_t dot = q.name.find('.', start);
        size_t labelLen = dot == std::string::npos
                              ? q.name.size() - start
                              : dot - start;
        questionLen += 1 + labelLen;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    questionLen += 4;  // qtype + qclass
    const size_t total = 12 + questionLen;
    if (!out || total > cap) return 0;

    std::memset(out, 0, total);
    out[0] = static_cast<uint8_t>(q.id >> 8);
    out[1] = static_cast<uint8_t>(q.id & 0xFF);
    out[2] = static_cast<uint8_t>(0x80 | (q.recursionDesired ? 0x01 : 0x00));
    out[3] = 0x80;  // RA; RCODE=NOERROR
    out[5] = 1;     // QDCOUNT=1; AN/NS/AR stay zero

    size_t pos = 12;
    writeName(q.name, out, pos);
    out[pos++] = static_cast<uint8_t>(q.type >> 8);
    out[pos++] = static_cast<uint8_t>(q.type & 0xFF);
    out[pos++] = 0;
    out[pos++] = 1;  // IN
    return total;
}

bool nameHasAddress(const DnsCache& cache, const std::string& name,
                    uint32_t ipHost, int64_t nowMs) {
    auto equalName = [](const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            const auto lower = [](char c) {
                return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
            };
            if (lower(a[i]) != lower(b[i])) return false;
        }
        return true;
    };
    for (const auto& [cachedName, answer] : cache) {
        if (nowMs - answer.second > kStaleGraceMs || !equalName(name, cachedName)) continue;
        for (uint32_t ip : answer.first) {
            if (ip == ipHost) return true;
        }
    }
    return false;
}

std::optional<std::string> reverseLookup(const DnsCache& cache, uint32_t ipHost,
                                         int64_t nowMs) {
    for (const auto& [name, entry] : cache) {
        if (entry.second <= nowMs) continue;  // expired entry
        for (uint32_t ip : entry.first) {
            if (ip == ipHost) return name;
        }
    }
    return std::nullopt;
}

std::vector<uint32_t> parseARecords(const uint8_t* pkt, size_t len) {
    std::vector<uint32_t> out;
    if (!pkt || len < 12) return out;
    size_t pos = 12;
    auto skipName = [&]() -> bool {
        std::string n;
        return readName(pkt, len, pos, n);
    };
    // Question section: skip every question (name + type + class).
    uint16_t qd = static_cast<uint16_t>((pkt[4] << 8) | pkt[5]);
    for (uint16_t i = 0; i < qd; ++i) {
        if (!skipName() || pos + 4 > len) return out;
        pos += 4;
    }
    // Walk every RR in the remaining sections: answer, authority,
    // additional. Only A records (type 1, rdlen 4) are collected.
    while (pos + 10 <= len) {
        if (!skipName()) return out;
        if (pos + 10 > len) return out;
        uint16_t type = static_cast<uint16_t>((pkt[pos] << 8) | pkt[pos + 1]);
        uint16_t rdlen = static_cast<uint16_t>((pkt[pos + 8] << 8) | pkt[pos + 9]);
        pos += 10;
        if (pos + rdlen > len) return out;
        if (type == 1 && rdlen == 4) {
            uint32_t ip = (static_cast<uint32_t>(pkt[pos]) << 24) |
                          (static_cast<uint32_t>(pkt[pos + 1]) << 16) |
                          (static_cast<uint32_t>(pkt[pos + 2]) << 8) |
                          static_cast<uint32_t>(pkt[pos + 3]);
            out.push_back(ip);
        }
        pos += rdlen;
    }
    return out;
}

std::optional<AResponse> parseAResponse(const uint8_t* pkt, size_t len) {
    if (!pkt || len < 17) return std::nullopt;
    const auto u16 = [&](size_t p) -> uint16_t {
        return static_cast<uint16_t>((pkt[p] << 8) | pkt[p + 1]);
    };
    const uint16_t flags = u16(2);
    if (!(flags & 0x8000) || (flags & 0x7A0F) || u16(4) != 1)
        return std::nullopt;  // response, standard opcode, no TC/error
    auto nameAt = [&](size_t& cursor, std::string& name) {
        size_t p = cursor;
        bool jumped = false;
        name.clear();
        for (size_t steps = 0; steps < 128 && p < len; ++steps) {
            const uint8_t n = pkt[p++];
            if (n == 0) {
                if (!jumped) cursor = p;
                return !name.empty();
            }
            if ((n & 0xC0) == 0xC0) {
                if (p >= len) return false;
                const size_t target = ((n & 0x3F) << 8) | pkt[p++];
                if (target >= p - 2) return false; // no forward/self cycles
                if (!jumped) cursor = p;
                jumped = true;
                p = target;
                continue;
            }
            if (n > 63 || p + n > len) return false;
            if (!name.empty()) name += '.';
            for (size_t i = 0; i < n; ++i) {
                char c = static_cast<char>(pkt[p++]);
                if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
                if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') &&
                    c != '-' && c != '_') return false;
                name += c;
            }
            if (name.size() > 253) return false;
        }
        return false;
    };
    AResponse result;
    result.id = u16(0);
    result.ttl = 300;
    size_t pos = 12;
    if (!nameAt(pos, result.name) || pos + 4 > len ||
        u16(pos) != 1 || u16(pos + 2) != 1) return std::nullopt;
    pos += 4;
    struct Record { std::string name, alias; uint32_t ip = 0, ttl = 0; };
    std::vector<Record> records;
    const uint16_t count = u16(6);
    if (count > 128) return std::nullopt;
    for (uint16_t i = 0; i < count; ++i) {
        Record r;
        if (!nameAt(pos, r.name) || pos + 10 > len) return std::nullopt;
        const uint16_t type = u16(pos), cls = u16(pos + 2), size = u16(pos + 8);
        r.ttl = (uint32_t(pkt[pos + 4]) << 24) | (uint32_t(pkt[pos + 5]) << 16) |
                (uint32_t(pkt[pos + 6]) << 8) | pkt[pos + 7];
        pos += 10;
        const size_t end = pos + size;
        if (end > len) return std::nullopt;
        if (cls == 1 && type == 1 && size == 4) {
            r.ip = (uint32_t(pkt[pos]) << 24) | (uint32_t(pkt[pos + 1]) << 16) |
                   (uint32_t(pkt[pos + 2]) << 8) | pkt[pos + 3];
            records.push_back(r);
        } else if (cls == 1 && type == 5) {
            size_t p = pos;
            if (!nameAt(p, r.alias) || p != end) return std::nullopt;
            records.push_back(r);
        }
        pos = end;
    }
    std::set<std::string> chain{result.name};
    for (size_t i = 0; i < records.size(); ++i) {
        bool changed = false;
        for (const auto& r : records) {
            if (!r.alias.empty() && chain.count(r.name)) {
                changed |= chain.insert(r.alias).second;
                result.ttl = std::min(result.ttl, r.ttl);
            }
        }
        if (!changed) break;
    }
    for (const auto& r : records) {
        if (r.alias.empty() && chain.count(r.name)) {
            result.ips.push_back(r.ip);
            result.ttl = std::min(result.ttl, r.ttl);
        }
    }
    if (result.ips.empty()) return std::nullopt;
    return result;
}

}  // namespace aps::dns
