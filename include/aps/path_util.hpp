// Filesystem / path helpers. Windows paths are case-insensitive; all rule
// matching flows through the canonical forms produced here.
#pragma once

#include <optional>
#include <string>

namespace aps {

// Lower-cased, backslash-normalized form used for comparisons only
// (the original casing is preserved everywhere it is displayed).
std::wstring canonicalPathKey(const std::wstring& path);

// Final path component ("C:\a\b\CC.exe" -> "CC.exe").
std::wstring baseName(const std::wstring& path);

// Directory containing the file, with trailing separator removed.
std::wstring dirName(const std::wstring& path);

// Case-insensitive full-path equality.
bool samePath(const std::wstring& a, const std::wstring& b);

// True when `child` is inside directory `dir` (or equals it).
bool pathIsUnder(const std::wstring& child, const std::wstring& dir);

// Absolute path of the running executable.
std::wstring currentModulePath();

// %LOCALAPPDATA%\AppProxySwitch (created if missing); empty on failure.
std::wstring appDataDir();

// Ensure all components of `dir` exist.
bool ensureDirectory(const std::wstring& dir);

// Generate a random id like "3f2b8c1e-..." (GUID based).
std::string newId();

// Version-robust rule path: directory segments that embed a version token
// (x.y.z..., optionally v-prefixed) are truncated to "<prefix>*", so the
// rule survives app auto-updates. Store apps are the canonical case:
// "...\OpenAI.Codex_26.818.3698.0_x64__hash\app\ChatGPT.exe" becomes
// "...\OpenAI.Codex*\app\ChatGPT.exe". The FILENAME is never touched.
// Segments without a version token (>= 3 dotted numeric components) stay
// unchanged. Used automatically when adding rules from the EXE browse or
// the running-process picker.
std::wstring versionRobustPath(const std::wstring& path);

// Parse "1.2.3.4" into host-byte-order uint32.
std::optional<uint32_t> parseIpv4(const std::string& text);
// Format host-byte-order uint32 as dotted string.
std::string formatIpv4(uint32_t ip);

// True for 127.0.0.0/8.
bool isLoopbackIpv4(uint32_t ipHostOrder);
// True for RFC1918 + link-local + loopback (private/local ranges).
bool isPrivateIpv4(uint32_t ipHostOrder);
// True for multicast 224.0.0.0/4 and limited broadcast 255.255.255.255.
// Network-critical destinations that must NEVER be proxied (they are not
// routable through an egress anyway; even "block"-action rules let them
// through). 0.0.0.0/8 is already covered by isPrivateIpv4.
bool isNeverProxyIpv4(uint32_t ipHostOrder);

}  // namespace aps
