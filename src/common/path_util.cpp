#include "aps/path_util.hpp"

#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cwctype>
#include <vector>

#include "aps/string_util.hpp"

namespace aps {

std::wstring canonicalPathKey(const std::wstring& path) {
    std::wstring out;
    out.reserve(path.size());
    for (wchar_t c : path) {
        if (c == L'/') c = L'\\';
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        out.push_back(c);
    }
    // Strip trailing separator (but keep "C:\" intact).
    while (out.size() > 3 && out.back() == L'\\') out.pop_back();
    return out;
}

std::wstring baseName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

std::wstring dirName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return L".";
    if (pos == 2 && path[1] == L':') return path.substr(0, 3);  // "C:\"
    return path.substr(0, pos);
}

bool samePath(const std::wstring& a, const std::wstring& b) {
    return canonicalPathKey(a) == canonicalPathKey(b);
}

bool pathIsUnder(const std::wstring& child, const std::wstring& dir) {
    std::wstring c = canonicalPathKey(child);
    std::wstring d = canonicalPathKey(dir);
    if (!c.empty() && c.back() != L'\\') c.push_back(L'\\');
    if (d.empty() || d.back() == L'\\') {
        while (!d.empty() && d.back() == L'\\') d.pop_back();
    }
    if (d.size() >= c.size()) return false;
    return c.compare(0, d.size(), d) == 0;
}

std::wstring currentModulePath() {
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) return {};
    return std::wstring(buf, n);
}

std::wstring appDataDir() {
    PWSTR roaming = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &roaming)) || !roaming) {
        return {};
    }
    std::wstring dir = roaming;
    CoTaskMemFree(roaming);
    dir += L"\\AppProxySwitch";
    if (!ensureDirectory(dir)) return {};
    return dir;
}

bool ensureDirectory(const std::wstring& dir) {
    if (dir.empty()) return false;
    DWORD attrs = GetFileAttributesW(dir.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return true;
    // Recursively create parents.
    std::wstring parent = dirName(dir);
    if (!parent.empty() && parent != dir && !samePath(parent, dir)) {
        if (!ensureDirectory(parent)) return false;
    }
    return CreateDirectoryW(dir.c_str(), nullptr) != 0 ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

std::string newId() {
    GUID g;
    if (FAILED(CoCreateGuid(&g))) {
        // Extremely unlikely; fall back to a clock-based id.
        char buf[64];
        std::snprintf(buf, sizeof(buf), "id-%llu", static_cast<unsigned long long>(GetTickCount64()));
        return buf;
    }
    wchar_t w[64];
    StringFromGUID2(g, w, 64);
    std::wstring ws(w);
    // Strip braces, lowercase.
    std::string s = wideToUtf8(ws);
    std::string out;
    for (char c : s) {
        if (c == '{' || c == '}') continue;
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        out.push_back(c);
    }
    return out;
}

std::optional<uint32_t> parseIpv4(const std::string& text) {
    IN_ADDR a;
    if (inet_pton(AF_INET, text.c_str(), &a) != 1) return std::nullopt;
    uint32_t net = a.S_un.S_addr;                // network byte order
    return static_cast<uint32_t>((net & 0xFF) << 24 | (net & 0xFF00) << 8 |
                                 (net & 0xFF0000) >> 8 | (net & 0xFF000000) >> 24);
}

std::string formatIpv4(uint32_t ipHostOrder) {
    IN_ADDR a;
    uint32_t net = ((ipHostOrder & 0xFF) << 24) | ((ipHostOrder & 0xFF00) << 8) |
                   ((ipHostOrder & 0xFF0000) >> 8) | ((ipHostOrder & 0xFF000000) >> 24);
    a.S_un.S_addr = net;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

bool isLoopbackIpv4(uint32_t ip) {
    return (ip >> 24) == 127;
}

bool isPrivateIpv4(uint32_t ip) {
    uint8_t a = static_cast<uint8_t>(ip >> 24);
    uint8_t b = static_cast<uint8_t>(ip >> 16);
    if (a == 127) return true;                // loopback
    if (a == 10) return true;                 // 10/8
    if (a == 192 && b == 168) return true;    // 192.168/16
    if (a == 172 && b >= 16 && b <= 31) return true;  // 172.16/12
    if (a == 169 && b == 254) return true;    // link-local
    if (a == 0) return true;                  // "this" network
    return false;
}

bool isNeverProxyIpv4(uint32_t ip) {
    uint8_t a = static_cast<uint8_t>(ip >> 24);
    if (a >= 224 && a <= 239) return true;    // multicast 224.0.0.0/4
    return ip == 0xFFFFFFFF;                  // limited broadcast
}

namespace {
// Start offset of the first version token in `seg` (npos when none):
// [vV]?digit+(.digit+){2,} — at least THREE dotted numeric components, so
// plain "2.0" or "7" directories never get wildcarded by accident.
size_t findVersionToken(const std::wstring& seg) {
    for (size_t i = 0; i < seg.size(); ++i) {
        size_t j = i;
        if ((seg[j] == L'v' || seg[j] == L'V') && j + 1 < seg.size() &&
            iswdigit(seg[j + 1])) {
            ++j;
        }
        if (j >= seg.size() || !iswdigit(seg[j])) continue;
        size_t start = j;
        int dots = 0;
        size_t k = j;
        while (k < seg.size()) {
            if (iswdigit(seg[k])) {
                ++k;
                continue;
            }
            if (seg[k] == L'.' && k + 1 < seg.size() && iswdigit(seg[k + 1])) {
                ++dots;
                ++k;
                continue;
            }
            break;
        }
        if (dots >= 2 && k > start) return start;
        i = k;  // skip the scanned run
    }
    return std::wstring::npos;
}

// True when the segment is a bare hex hash of at least 8 chars (Codex
// installs under bin\<sha-hash>\codex.exe and ROTATES the hash on every
// self-update — measured 2026-09-01: the rule's exact path went stale
// overnight and every work-mode session silently went direct).
bool isHexHashSegment(const std::wstring& seg) {
    if (seg.size() < 8 || seg.size() > 64) return false;
    for (wchar_t c : seg) {
        if (!iswxdigit(c)) return false;
    }
    return true;
}
}  // namespace

std::wstring versionRobustPath(const std::wstring& path) {
    std::vector<std::wstring> segs;
    std::wstring cur;
    for (wchar_t c : path) {
        if (c == L'\\' || c == L'/') {
            if (!cur.empty()) segs.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) segs.push_back(cur);  // the filename (never touched)
    if (segs.size() < 2) return path;

    for (size_t i = 0; i + 1 < segs.size(); ++i) {  // dirs only
        if (isHexHashSegment(segs[i])) {
            segs[i] = L"*";
            continue;
        }
        size_t cut = findVersionToken(segs[i]);
        if (cut == std::wstring::npos) continue;
        // A v-prefix (v2.3.4 / app-v2.3.4) belongs to the version token:
        // drop it too — but only when it is a real prefix (start of segment
        // or right after a separator), not the tail of a word like "sv".
        if (cut > 0 && (segs[i][cut - 1] == L'v' || segs[i][cut - 1] == L'V') &&
            (cut == 1 || segs[i][cut - 2] == L'-' || segs[i][cut - 2] == L'_' ||
             segs[i][cut - 2] == L'.' || segs[i][cut - 2] == L' ')) {
            --cut;
        }
        std::wstring prefix = segs[i].substr(0, cut);
        while (!prefix.empty() &&
               (prefix.back() == L'-' || prefix.back() == L'_' ||
                prefix.back() == L'.' || prefix.back() == L' ')) {
            prefix.pop_back();
        }
        segs[i] = prefix + L"*";
    }
    std::wstring out;
    for (size_t i = 0; i < segs.size(); ++i) {
        if (i) out.push_back(L'\\');
        out += segs[i];
    }
    return out;
}

}  // namespace aps
