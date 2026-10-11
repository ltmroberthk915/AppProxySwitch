#include "aps/verge_subscription.hpp"
#include "aps/clash_pipe.hpp"
#include <algorithm>
#include <format>
#include <random>

namespace aps {
namespace {
std::string str(const json::Value& v, const char* key) {
    const auto* p = v.find(key); return p ? p->asString() : std::string();
}
bool number(const json::Value& v, const char* key, uint32_t expected) {
    const auto* p = v.find(key); return p && p->isNumber() && p->asNumber() == expected;
}
bool boolean(const json::Value& v, const char* key, bool expected) {
    const auto* p = v.find(key); return p && p->isBoolean() && p->asBool() == expected;
}
bool safeCode(const std::string& code) {
    return !code.empty() && code.size() <= 96 &&
        std::all_of(code.begin(), code.end(), [](char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
}
bool exchange(const std::string& pipe, uint32_t expectedPid, const json::Value& request,
              uint32_t& owner, json::Value& result, std::string& error) {
    std::string response;
    if (!requestProfileBridgePipe(pipe, expectedPid, request.dump() + "\n", 1500,
                                  owner, response, error)) return false;
    if (!json::Value::parse(response, result, nullptr)) {
        error = "invalid_bridge_reply"; return false;
    }
    return true;
}
}

bool validateVergeBridgeInfo(const json::Value& info, const DiscoveredKernel& kernel,
                            uint32_t serverPid, json::Value& identity) {
    const auto* id = info.find("identity");
    const auto* caps = info.find("capabilities");
    bool capable = caps && caps->isArray() && std::any_of(caps->array().begin(), caps->array().end(),
        [](const json::Value& v) { return v.asString() == "refresh_current_no_restart"; });
    if (!serverPid || !kernel.pid || !localControllerPipe(kernel.apiPipe) ||
        !number(info, "protocol", 1) || str(info, "state") != "ready" ||
        !number(info, "client_pid", serverPid) || !capable || !id || !id->isObject() ||
        !number(*id, "core_pid", kernel.pid) || str(*id, "controller_pipe") != kernel.apiPipe ||
        str(*id, "profile_uid").empty() || str(*id, "profile_uid").size() > 128 ||
        str(*id, "revision").empty() || str(*id, "revision").size() > 128) return false;
    identity = *id;
    return true;
}

VergeRefreshState validateVergeRefreshReply(const json::Value& reply,
    const std::string& requestId, std::string& error) {
    if (!number(reply, "protocol", 1)) { error = "invalid_bridge_reply"; return VergeRefreshState::Unconfirmed; }
    const auto state = str(reply, "state");
    // Request validation / busy responses can precede creation of a job.
    if (state == "error") {
        const auto returnedId = str(reply, "request_id");
        if (!returnedId.empty() && returnedId != requestId) { error = "invalid_bridge_reply"; return VergeRefreshState::Unconfirmed; }
        const auto code = str(reply, "code");
        error = safeCode(code) ? code : "invalid_bridge_error";
        return VergeRefreshState::Failed;
    }
    if (str(reply, "request_id") != requestId) { error = "invalid_bridge_reply"; return VergeRefreshState::Unconfirmed; }
    if (state == "running") return VergeRefreshState::Running;
    if (state == "ok" && boolean(reply, "downloaded", true) && boolean(reply, "saved", true) &&
        boolean(reply, "applied", true) && boolean(reply, "restarted", false)) return VergeRefreshState::Succeeded;
    error = "incomplete_success_reply";
    return VergeRefreshState::Unconfirmed;
}

bool prepareVergeSubscription(const DiscoveredKernel& kernel,
                             VergeSubscriptionTicket& ticket, std::string& error) {
    if (!kernel.pid || !localControllerPipe(kernel.apiPipe)) { error = "no_verified_controller"; return false; }
    ticket = {};
    ticket.pipe = kernel.apiPipe + ".aps-profile-v1";
    auto request = json::Value::makeObject();
    request.set("protocol", 1);
    request.set("op", "info");
    json::Value reply;
    if (!exchange(ticket.pipe, 0, request, ticket.clientPid, reply, error)) {
        error = "cooperation_client_unavailable"; return false;
    }
    if (str(reply, "state") == "error" && number(reply,"protocol",1)) {
        auto code = str(reply,"code"); error = safeCode(code) ? code : "invalid_bridge_error"; return false;
    }
    if (!validateVergeBridgeInfo(reply, kernel, ticket.clientPid, ticket.identity)) {
        error = "bridge_target_mismatch"; return false;
    }
    std::random_device rng;
    ticket.requestId = std::format("{:08x}{:08x}{:08x}{:08x}", rng(), rng(), rng(), rng());
    return true;
}

VergeRefreshState advanceVergeSubscription(VergeSubscriptionTicket& ticket, std::string& error) {
    auto request = json::Value::makeObject();
    request.set("protocol", 1);
    request.set("op", ticket.submitted ? "status" : "refresh_current");
    request.set("request_id", ticket.requestId);
    if (!ticket.submitted) request.set("expected", ticket.identity);
    // A lost submit reply is uncertain: poll this SAME job, never submit a
    // different ID and never interpret a timeout as successful completion.
    ticket.submitted = true;
    uint32_t owner = 0;
    json::Value reply;
    if (!exchange(ticket.pipe, ticket.clientPid, request, owner, reply, error)) {
        error = "bridge_response_unconfirmed"; return VergeRefreshState::Unconfirmed;
    }
    return validateVergeRefreshReply(reply, ticket.requestId, error);
}

std::string vergeRefreshExplanation(const std::string& code) {
    if (code == "cooperation_client_unavailable") return "当前 Clash Verge 未运行 APS 订阅协作接口；需使用配套协作版本，未修改配置或重启内核";
    if (code == "no_current_remote_profile") return "Clash Verge 当前未选中可更新的远程订阅；未作修改";
    if (code == "download_failed_no_changes") return "Verge 直连及自身代理下载均失败；保留原订阅，未使用其他客户端代理端口，未重启内核";
    if (code == "busy" || code == "client_busy_no_changes") return "Verge 正在处理另一项配置操作，请稍后重试；未启动本次更新";
    if (code == "bridge_target_mismatch" || code == "target_changed_no_changes") return "内核或订阅身份已变化；本次更新未执行，请重新确认目标";
    if (code == "hot_reload_failed_rolled_back_no_restart") return "热加载失败，已恢复原配置并重新热加载；未重启内核";
    if (code == "validation_failed" || code == "enhancement_failed") return "新订阅未通过 Verge 增强/校验，已恢复原文件，未重启内核";
    // Only fixed protocol codes cross IPC; raw URL-bearing errors never do.
    return "Verge 更新未确认成功：" + (safeCode(code) ? code : "bridge_error") + "；请查看 Verge 客户端，不会自动重启或切换出口";
}
}
