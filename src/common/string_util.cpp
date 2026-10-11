#include "aps/string_util.hpp"

#include <windows.h>

namespace aps {

std::wstring utf8ToWide(std::string_view utf8) {
    if (utf8.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                  static_cast<int>(utf8.size()), nullptr, 0);
    if (len <= 0) {
        // Fallback: replace invalid sequences instead of failing outright.
        len = MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                  static_cast<int>(utf8.size()), nullptr, 0);
    }
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
                        out.data(), len);
    return out;
}

std::string wideToUtf8(std::wstring_view wide) {
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                  static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                        out.data(), len, nullptr, nullptr);
    return out;
}

std::string toLowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::wstring toLowerAsciiW(std::wstring s) {
    for (wchar_t& c : s) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    return s;
}

bool equalsIgnoreCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

bool startsWithIgnoreCase(std::string_view haystack, std::string_view prefix) {
    if (prefix.size() > haystack.size()) return false;
    return equalsIgnoreCase(haystack.substr(0, prefix.size()), prefix);
}

bool endsWithIgnoreCase(std::string_view haystack, std::string_view suffix) {
    if (suffix.size() > haystack.size()) return false;
    return equalsIgnoreCase(haystack.substr(haystack.size() - suffix.size()), suffix);
}

std::string_view trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(kBase64Chars[(v >> 18) & 63]);
        out.push_back(kBase64Chars[(v >> 12) & 63]);
        out.push_back(kBase64Chars[(v >> 6) & 63]);
        out.push_back(kBase64Chars[v & 63]);
        i += 3;
    }
    if (len - i == 1) {
        uint32_t v = data[i] << 16;
        out.push_back(kBase64Chars[(v >> 18) & 63]);
        out.push_back(kBase64Chars[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (len - i == 2) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(kBase64Chars[(v >> 18) & 63]);
        out.push_back(kBase64Chars[(v >> 12) & 63]);
        out.push_back(kBase64Chars[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

static int base64CharValue(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool base64Decode(std::string_view in, std::vector<uint8_t>& out) {
    out.clear();
    // Strip whitespace; validate padding.
    std::string compact;
    compact.reserve(in.size());
    for (char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        compact.push_back(c);
    }
    if (compact.empty()) return true;  // "" encodes zero bytes
    if (compact.size() % 4 != 0) return false;
    size_t pad = 0;
    if (compact.back() == '=') ++pad;
    if (compact.size() >= 2 && compact[compact.size() - 2] == '=') ++pad;
    uint32_t acc = 0;
    int bits = 0;
    size_t outLen = 0;
    for (size_t i = 0; i < compact.size(); ++i) {
        if (compact[i] == '=') {
            if (i < compact.size() - pad) return false;  // '=' in the middle
            continue;
        }
        int v = base64CharValue(compact[i]);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
            ++outLen;
        }
    }
    // Check canonical padding length.
    if (pad != 0 && pad != 1 && pad != 2) return false;
    return true;
}

}  // namespace aps
