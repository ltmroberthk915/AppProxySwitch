// IPC message definitions for the \\.\pipe\AppProxySwitchCtrl pipe protocol.
// One JSON object per line (UTF-8, \n-terminated, max 64 KiB per line).
#pragma once

#include <string>

#include "aps/json.hpp"

namespace aps::ipc {

constexpr int kProtoVersion = 1;
constexpr size_t kMaxLine = 64 * 1024;

// ---- client -> engine --------------------------------------------------------
inline std::string hello(uint32_t pid, const std::string& version) {
    json::Value m = json::Value::makeObject();
    m.set("type", "HELLO");
    m.set("proto", kProtoVersion);
    m.set("pid", pid);
    m.set("gui_version", version);
    return m.dump();
}
inline std::string reload() {
    json::Value m = json::Value::makeObject();
    m.set("type", "RELOAD");
    return m.dump();
}
inline std::string stop() {
    json::Value m = json::Value::makeObject();
    m.set("type", "STOP");
    return m.dump();
}
inline std::string flush(const std::string& ruleId = "") {
    json::Value m = json::Value::makeObject();
    m.set("type", "FLUSH");
    m.set("rule_id", ruleId);
    return m.dump();
}
inline std::string getStatus(int64_t id) {
    json::Value m = json::Value::makeObject();
    m.set("type", "GETSTATUS");
    m.set("id", id);
    return m.dump();
}
inline std::string getStats(int64_t id) {
    json::Value m = json::Value::makeObject();
    m.set("type", "GETSTATS");
    m.set("id", id);
    return m.dump();
}
inline std::string setEnabled(bool enabled) {
    json::Value m = json::Value::makeObject();
    m.set("type", "SET_ENABLED");
    m.set("enabled", enabled);
    return m.dump();
}
// GUI: "测速并切换" — immediate node-monitor round (auto-switch rules apply).
// outletId: which outlet to probe ("" = all).
inline std::string nodeSwitch(const std::string& outletId = "", const std::string& requestId = "") {
    json::Value m = json::Value::makeObject();
    m.set("type", "NODESWITCH");
    m.set("outlet", outletId);
    if (!requestId.empty()) m.set("request_id", requestId);
    return m.dump();
}
// GUI window visibility gate: the per-second STATS push only runs while the
// window is actually visible (power saving — a tray-hidden window has no
// consumer for connection snapshots). The engine still pushes rare STATUS
// events and runs all real work (NAT sweep, node monitoring) unaffected.
inline std::string setVisible(bool visible) {
    json::Value m = json::Value::makeObject();
    m.set("type", "SET_VISIBLE");
    m.set("visible", visible);
    return m.dump();
}
// GUI: "刷新订阅" — re-fetch the airport subscription and hot-reload the
// kernel via PUT /configs (mimics the kernel GUI's own refresh).
inline std::string subRefresh() {
    json::Value m = json::Value::makeObject();
    m.set("type", "SUBREFRESH");
    return m.dump();
}

// ---- engine -> client ----------------------------------------------------------
inline std::string welcome(bool admin, const std::string& version,
                           const std::string& state) {
    json::Value m = json::Value::makeObject();
    m.set("type", "WELCOME");
    m.set("proto", kProtoVersion);
    m.set("admin", admin);
    m.set("engine_version", version);
    m.set("state", state);
    return m.dump();
}
inline std::string bye(const std::string& reason) {
    json::Value m = json::Value::makeObject();
    m.set("type", "BYE");
    m.set("reason", reason);
    return m.dump();
}
inline std::string error(int64_t id, const std::string& code) {
    json::Value m = json::Value::makeObject();
    m.set("type", "ERROR");
    m.set("id", id);
    m.set("code", code);
    return m.dump();
}

// Strict parse of one received line. Returns false for anything that is not a
// well-formed, whitelisted message (unknown types are rejected, unknown
// fields are ignored by design).
bool parseMessage(const std::string& line, json::Value& out, std::string* errType);

}  // namespace aps::ipc
