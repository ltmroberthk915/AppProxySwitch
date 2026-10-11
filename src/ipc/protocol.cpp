#include "aps/protocol.hpp"

#include <set>

namespace aps::ipc {

bool parseMessage(const std::string& line, json::Value& out, std::string* errType) {
    if (line.empty() || line.size() > kMaxLine) {
        if (errType) *errType = "bad_size";
        return false;
    }
    std::string perr;
    if (!json::Value::parse(line, out, &perr)) {
        if (errType) *errType = "bad_json";
        return false;
    }
    if (!out.isObject()) {
        if (errType) *errType = "bad_shape";
        return false;
    }
    const json::Value* t = out.find("type");
    if (!t || !t->isString()) {
        if (errType) *errType = "bad_type";
        return false;
    }
    static const std::set<std::string> kAllowed = {
        "HELLO", "RELOAD", "STOP", "FLUSH", "GETSTATUS", "GETSTATS", "SET_ENABLED",
        "NODESWITCH", "SET_VISIBLE", "SUBREFRESH", "WELCOME", "STATUS", "STATS",
        "LOG", "BYE", "ERROR",
    };
    if (!kAllowed.count(t->asString())) {
        if (errType) *errType = "unknown_type";
        return false;
    }
    // Cap string fields defensively (defense in depth against junk input).
    for (const auto& kv : out.object()) {
        if (kv.second.isString() && kv.second.asString().size() > 8192) {
            if (errType) *errType = "field_too_long";
            return false;
        }
    }
    return true;
}

}  // namespace aps::ipc
