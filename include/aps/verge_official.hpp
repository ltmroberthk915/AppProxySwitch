#pragma once
#include "aps/kernel_discovery.hpp"
#include <stop_token>
#include <filesystem>
#include <vector>

namespace aps {
struct VergeProfile { std::string uid, name, file, updated; bool remote = false; };
bool parseVergeProfiles(const std::string& yaml, std::string& current,
                        std::vector<VergeProfile>& profiles);
struct VergeUpdateEvidence {
    std::string uid;
    bool started=false, downloaded=false, applied=false, ambiguous=false, failed=false;
    void consume(const std::string& line);
};
struct VergeInstanceRecord { uint16_t port=0; std::string token; };
bool parseVergeInstanceRecord(const std::string& text, VergeInstanceRecord& record);
bool vergeActionLabelMatches(const std::string& label,
    const std::vector<std::string>& actions);
// The official service and sidecar use different prefixes for the same
// per-user owner key. Empty means an unknown/legacy naming scheme.
std::string vergeControllerOwnerKey(const std::string& pipe);
bool vergeControllerMatchesRuntime(const DiscoveredKernel& kernel,
    const std::string& runtimeYaml);
// Read-only pairing: PID-verified /version plus the same user's GUI runtime
// endpoint. Supports cores staged outside the GUI's installation directory.
bool resolveOfficialVergeClient(const DiscoveredKernel& kernel,
    uint32_t& clientPid, std::filesystem::path& dataDir, std::string& error);
// Caller authenticates the GUI and data directory. A new client's instance
// record selects a PID-owned port and supplies its local activation credential.
// Without a record, retain the legacy unique-listener protocol. Never retry a
// request, follow redirects, log a credential, or send it to a different PID.
bool requestOfficialVergeWindow(uint32_t clientPid,
    const std::filesystem::path& dataDir = {}, std::string* diagnostic = nullptr);
// Reuse an already visible main window independently of the singleton protocol.
// Returns a native HWND as uintptr_t so consumers need no Windows headers.
uintptr_t ensureOfficialVergeWindow(uint32_t clientPid,
    const std::filesystem::path& dataDir, std::stop_token stop = {},
    std::string* diagnostic = nullptr);
enum class VergeSavedState { Unchanged, Saved, Conflict };
VergeSavedState verifyVergeProfileChange(const std::string& uid,
    const std::string& originalCurrent, const std::vector<VergeProfile>& before,
    const std::string& nowCurrent, const std::vector<VergeProfile>& now,
    bool fileChanged);
// Official client UI only. Never writes Verge configuration, starts/stops its
// processes, injects code, changes a node, or invokes "update all".
// Empty requestedUid means the CURRENT profile of the selected kernel.
std::string refreshOfficialVerge(const DiscoveredKernel& kernel,
    std::stop_token stop = {}, const std::string& requestedUid = {});
}
