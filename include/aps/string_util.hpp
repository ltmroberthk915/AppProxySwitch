// String / encoding utilities shared by all components.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aps {

// UTF-8 <-> UTF-16 conversions (Win32 MultiByteToWideChar based).
std::wstring utf8ToWide(std::string_view utf8);
std::string wideToUtf8(std::wstring_view wide);

// ASCII-case-insensitive helpers (paths and exe names on Windows are
// case-insensitive; non-ASCII bytes are compared as-is).
std::string toLowerAscii(std::string s);
std::wstring toLowerAsciiW(std::wstring s);
bool equalsIgnoreCase(std::string_view a, std::string_view b);
bool startsWithIgnoreCase(std::string_view haystack, std::string_view prefix);
bool endsWithIgnoreCase(std::string_view haystack, std::string_view suffix);

std::string_view trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char sep);

// Base64 (standard alphabet, with padding).
std::string base64Encode(const uint8_t* data, size_t len);
bool base64Decode(std::string_view in, std::vector<uint8_t>& out);

}  // namespace aps
