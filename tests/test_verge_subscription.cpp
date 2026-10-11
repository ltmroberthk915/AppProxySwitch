#include "aps/verge_subscription.hpp"
#include "aps/verge_official.hpp"
#include "aps/clash_pipe.hpp"
#include "aps/clash_api.hpp"
#include "aps/region_detect.hpp"
#include "mock_profile_bridge.hpp"
#include "mock_http_server.hpp"
#include "testlib/appsw_test.h"
#include <fstream>
using namespace aps;

namespace {
struct InstanceFixture {
    std::filesystem::path dir;
    InstanceFixture() {
        wchar_t root[MAX_PATH]{}, temporary[MAX_PATH]{};
        GetTempPathW(MAX_PATH,root); GetTempFileNameW(root,L"aps",0,temporary);
        DeleteFileW(temporary); dir=temporary; std::filesystem::create_directory(dir);
    }
    ~InstanceFixture(){std::error_code ec;std::filesystem::remove_all(dir,ec);}
    void write(uint16_t port,const std::string& token) {
        auto record=json::Value::makeObject();record.set("port",static_cast<uint32_t>(port));record.set("token",token);
        std::ofstream(dir/L"singleton-instance.json")<<record.dump();
    }
};
}

APS_TEST(verge_profile, metadata_requires_matching_pid_pipe_and_capability) {
    test::MockProfileBridge bridge; EXPECT_TRUE(bridge.start());
    DiscoveredKernel kernel; kernel.pid = GetCurrentProcessId(); kernel.apiPipe = bridge.controllerPipe;
    json::Value identity;
    auto info = bridge.info();
    EXPECT_TRUE(validateVergeBridgeInfo(info,kernel,GetCurrentProcessId(),identity));
    EXPECT_FALSE(validateVergeBridgeInfo(info,kernel,GetCurrentProcessId()+1,identity));
    ++kernel.pid;
    EXPECT_FALSE(validateVergeBridgeInfo(info,kernel,GetCurrentProcessId(),identity));
    --kernel.pid; kernel.apiPipe += "wrong";
    EXPECT_FALSE(validateVergeBridgeInfo(info,kernel,GetCurrentProcessId(),identity));
    kernel.apiPipe = bridge.controllerPipe; info.set("capabilities",json::Value::makeArray());
    EXPECT_FALSE(validateVergeBridgeInfo(info,kernel,GetCurrentProcessId(),identity));
}

APS_TEST(verge_profile, false_success_is_rejected_and_errors_cannot_leak_urls) {
    auto reply = json::Value::makeObject();
    reply.set("protocol",1); reply.set("state","ok"); reply.set("request_id","id");
    std::string error;
    EXPECT_TRUE(validateVergeRefreshReply(reply,"id",error) == VergeRefreshState::Unconfirmed);
    reply.set("downloaded",true); reply.set("saved",true); reply.set("applied",true); reply.set("restarted",false);
    EXPECT_TRUE(validateVergeRefreshReply(reply,"id",error) == VergeRefreshState::Succeeded);
    reply.set("applied",false);
    EXPECT_TRUE(validateVergeRefreshReply(reply,"id",error) == VergeRefreshState::Unconfirmed);
    reply.set("state","error"); reply.set("code","https://secret.invalid/?token=private");
    EXPECT_TRUE(validateVergeRefreshReply(reply,"id",error) == VergeRefreshState::Failed);
    EXPECT_STREQ(error,"invalid_bridge_error");
    EXPECT_TRUE(vergeRefreshExplanation(error).find("token") == std::string::npos);
}

APS_TEST(verge_profile, pipe_roundtrip_submits_once_then_polls_same_request) {
    test::MockProfileBridge bridge;
    std::string submittedId;
    bridge.respond = [&](const json::Value& request) {
        if (request.find("op")->asString() == "info") return bridge.info();
        auto r = json::Value::makeObject();
        const auto id = request.find("request_id")->asString();
        r.set("protocol",1); r.set("request_id",id);
        if (request.find("op")->asString() == "refresh_current") {
            submittedId = id; r.set("state","running"); return r;
        }
        r.set("state","ok"); r.set("downloaded",true); r.set("saved",true); r.set("applied",true); r.set("restarted",false);
        return r;
    };
    EXPECT_TRUE(bridge.start());
    DiscoveredKernel kernel; kernel.pid = GetCurrentProcessId(); kernel.apiPipe = bridge.controllerPipe;
    VergeSubscriptionTicket ticket; std::string error;
    EXPECT_TRUE(prepareVergeSubscription(kernel,ticket,error));
    EXPECT_TRUE(advanceVergeSubscription(ticket,error) == VergeRefreshState::Running);
    EXPECT_TRUE(advanceVergeSubscription(ticket,error) == VergeRefreshState::Succeeded);
    EXPECT_EQ(bridge.submissions.load(),1);
    EXPECT_STREQ(ticket.requestId,submittedId);
}

APS_TEST(verge_profile, no_controller_never_guesses_a_port_or_other_client) {
    DiscoveredKernel kernel; kernel.pid = GetCurrentProcessId(); kernel.socksPort = 7897;
    VergeSubscriptionTicket ticket; std::string error;
    EXPECT_FALSE(prepareVergeSubscription(kernel,ticket,error));
    EXPECT_STREQ(error,"no_verified_controller");
}

APS_TEST(verge_profile, pipe_rejects_wrong_owner_before_sending_any_request) {
    test::MockProfileBridge bridge; EXPECT_TRUE(bridge.start());
    std::string reply,error; uint32_t owner = 0;
    EXPECT_FALSE(requestProfileBridgePipe(bridge.name,GetCurrentProcessId()+1,"{\"protocol\":1,\"op\":\"info\"}\n",300,owner,reply,error));
    EXPECT_EQ(bridge.submissions.load(),0);
}

APS_TEST(verge_official, parses_only_top_level_profile_fields) {
    std::string current; std::vector<VergeProfile> p;
    EXPECT_TRUE(parseVergeProfiles("current: R1\nitems:\n- uid: R1\n  type: remote\n  name: 'unique'\n  file: R1.yaml\n  selected:\n  - name: nested\n  updated: 123\n",current,p));
    EXPECT_STREQ(current,"R1"); EXPECT_EQ(p.size(),1u); EXPECT_STREQ(p[0].name,"unique"); EXPECT_TRUE(p[0].remote);
}
APS_TEST(verge_official, rejects_duplicate_uids_and_missing_current) {
    std::string c;std::vector<VergeProfile> p;
    EXPECT_FALSE(parseVergeProfiles("current: R\n- uid: R\n- uid: R\n",c,p));
    EXPECT_FALSE(parseVergeProfiles("- uid: R\n",c,p));
}
APS_TEST(verge_official, reload_success_is_not_download_success) {
    VergeUpdateEvidence e;e.uid="R";
    e.consume("[订阅更新] 开始更新订阅 R"); e.consume("[订阅更新] 更新成功");
    EXPECT_TRUE(e.applied);EXPECT_FALSE(e.downloaded);
    e.consume("[订阅更新] 使用 Clash代理 更新订阅配置成功");EXPECT_TRUE(e.downloaded);
}
APS_TEST(verge_official, rejects_interleaved_and_duplicate_refresh) {
    VergeUpdateEvidence e;e.uid="R";e.consume("[订阅更新] 开始更新订阅 X");
    e.consume("[订阅更新] 开始更新订阅 R");e.consume("[订阅更新] 更新订阅配置成功");
    EXPECT_TRUE(e.ambiguous);EXPECT_FALSE(e.downloaded);
    VergeUpdateEvidence d;d.uid="R";d.consume("[订阅更新] 开始更新订阅 R");d.consume("[订阅更新] 开始更新订阅 R");EXPECT_TRUE(d.ambiguous);
}
APS_TEST(verge_official, missing_identity_has_no_ui_or_network_side_effects) {
    DiscoveredKernel k;
    EXPECT_TRUE(refreshOfficialVerge(k).starts_with("error:"));
}

APS_TEST(verge_official, service_core_pairs_with_sidecar_runtime_by_owner_and_port) {
    DiscoveredKernel k;k.pid=123;k.socksPort=57364;
    k.apiPipe="\\\\.\\pipe\\verge-mihomo-production-0123456789abcdef0123456789abcdef";
    const std::string yaml="mixed-port: 57364\nexternal-controller-pipe: \\\\.\\pipe\\verge-mihomo-sidecar-release-0123456789abcdef0123456789abcdef\n";
    EXPECT_TRUE(vergeControllerMatchesRuntime(k,yaml));
    k.apiPipe="\\\\.\\pipe\\verge-mihomo-production-fedcba9876543210fedcba9876543210";
    EXPECT_FALSE(vergeControllerMatchesRuntime(k,yaml));
    k.apiPipe="\\\\.\\pipe\\verge-mihomo-production-0123456789abcdef0123456789abcdef";k.socksPort=57365;
    EXPECT_FALSE(vergeControllerMatchesRuntime(k,yaml));
    k.socksPort=57364;k.apiPipe="\\\\.\\pipe\\verge-mihomo-dev-0123456789abcdef0123456789abcdef";
    EXPECT_FALSE(vergeControllerMatchesRuntime(k,yaml));
    // Future channel/version prefixes are accepted from verified runtime
    // evidence without adding another release-specific string whitelist.
    k.apiPipe="\\\\.\\pipe\\renamed-controller-next-0123456789abcdef0123456789abcdef";
    EXPECT_TRUE(vergeControllerMatchesRuntime(k,yaml));
    k.apiPipe="\\\\.\\pipe\\renamed-controller-device-0123456789abcdef0123456789abcdef";
    EXPECT_TRUE(vergeControllerMatchesRuntime(k,yaml));
    k.apiPipe="\\\\.\\pipe\\verge-mihomo-production-";
    EXPECT_FALSE(vergeControllerMatchesRuntime(k,yaml));
}

APS_TEST(verge_official, legacy_and_identical_runtime_pipes_still_pair) {
    DiscoveredKernel k;k.socksPort=23456;k.apiPipe="\\\\.\\pipe\\verge-mihomo";
    EXPECT_TRUE(vergeControllerMatchesRuntime(k,"mixed-port: 23456\nexternal-controller-pipe: \\\\.\\pipe\\verge-mihomo\n"));
    EXPECT_FALSE(vergeControllerMatchesRuntime(k,"mixed-port: 23456\n"));
    EXPECT_FALSE(vergeControllerMatchesRuntime(k,"mixed-port: 0\nexternal-controller-pipe: \\\\.\\pipe\\verge-mihomo\n"));
    uint32_t clientPid=1;std::filesystem::path dir="C:\\wrong";std::string error;
    EXPECT_FALSE(resolveOfficialVergeClient(k,clientPid,dir,error)); // no PID: no request/UI
    EXPECT_EQ(clientPid,0u);EXPECT_TRUE(dir.empty());EXPECT_FALSE(error.empty());
}

APS_TEST(verge_official, accessible_action_names_tolerate_layout_and_localization_changes) {
    const std::vector<std::string> actions={"刷新", "Refresh", "刷新订阅", "Update subscription"};
    EXPECT_TRUE(vergeActionLabelMatches(" 刷 新 ",actions));
    EXPECT_TRUE(vergeActionLabelMatches("REFRESH…",actions));
    EXPECT_TRUE(vergeActionLabelMatches("Update\nsubscription...",actions));
    EXPECT_FALSE(vergeActionLabelMatches("Refresh all",actions));
    EXPECT_FALSE(vergeActionLabelMatches("刷新全部订阅",actions));
    EXPECT_FALSE(vergeActionLabelMatches("",actions));
    EXPECT_FALSE(vergeActionLabelMatches("Delete subscription",actions));
}

APS_TEST(verge_official, singleton_window_uses_dynamic_owner_port_once) {
    test::MockHttpServer server; server.setResponse("ok"); EXPECT_TRUE(server.start());
    EXPECT_TRUE(requestOfficialVergeWindow(GetCurrentProcessId()));
    EXPECT_EQ(server.hits(),1u);
}
APS_TEST(verge_official, singleton_window_rejects_unknown_identity_and_ambiguous_ports) {
    test::MockHttpServer a,b; a.setResponse("ok"); b.setResponse("ok");
    EXPECT_TRUE(a.start()); EXPECT_TRUE(b.start());
    EXPECT_FALSE(requestOfficialVergeWindow(0));
    EXPECT_FALSE(requestOfficialVergeWindow(GetCurrentProcessId()));
    EXPECT_EQ(a.hits(),0u); EXPECT_EQ(b.hits(),0u);
}
APS_TEST(verge_official, singleton_window_does_not_retry_unconfirmed_reply) {
    test::MockHttpServer server; server.setResponse("unexpected"); EXPECT_TRUE(server.start());
    EXPECT_FALSE(requestOfficialVergeWindow(GetCurrentProcessId()));
    EXPECT_EQ(server.hits(),1u);
}

APS_TEST(verge_official, instance_record_supports_extra_fields_and_token_formats) {
    VergeInstanceRecord record;
    EXPECT_TRUE(parseVergeInstanceRecord(R"({"port":23456,"token":"future-token_123=","new_field":true})",record));
    EXPECT_EQ(record.port,23456); EXPECT_STREQ(record.token,"future-token_123=");
    for(const auto* invalid:{R"({"port":0,"token":"a"})",R"({"port":65536,"token":"a"})",
        R"({"port":-1,"token":"a"})",R"({"port":2.5,"token":"a"})",R"({"port":"80","token":"a"})",
        R"({"port":80,"token":""})",R"({"port":80,"token":"a\r\nInjected:yes"})",
        R"({"port":80,"token":"a b"})",R"({"port":80})","[]","{broken"}) {
        EXPECT_FALSE(parseVergeInstanceRecord(invalid,record));
        EXPECT_EQ(record.port,0); EXPECT_TRUE(record.token.empty());
    }
    EXPECT_FALSE(parseVergeInstanceRecord(std::string(4097,' '),record));
}

APS_TEST(verge_official, authenticated_activation_uses_record_even_with_multiple_owned_ports) {
    InstanceFixture data; test::MockHttpServer server,other;
    server.setResponse("ok\n"); server.requireHeader("x-instance-token: local-token\r\n");
    EXPECT_TRUE(server.start()); EXPECT_TRUE(other.start()); data.write(server.port(),"local-token");
    std::string diagnostic;
    EXPECT_TRUE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir,&diagnostic));
    EXPECT_TRUE(diagnostic.empty()); EXPECT_EQ(server.hits(),1u); EXPECT_EQ(other.hits(),0u);
    EXPECT_STREQ(server.hit(0).requestLine,"GET /commands/visible HTTP/1.1");
}

APS_TEST(verge_official, record_is_reread_when_client_changes_port_and_token) {
    InstanceFixture data; test::MockHttpServer first,second;
    first.setResponse("ok"); second.setResponse("ok");
    first.requireHeader("x-instance-token: first\r\n"); second.requireHeader("x-instance-token: second\r\n");
    EXPECT_TRUE(first.start()); EXPECT_TRUE(second.start());
    data.write(first.port(),"first"); EXPECT_TRUE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir));
    data.write(second.port(),"second"); EXPECT_TRUE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir));
    EXPECT_EQ(first.hits(),1u); EXPECT_EQ(second.hits(),1u);
}

APS_TEST(verge_official, missing_record_keeps_legacy_and_bad_record_never_falls_back) {
    InstanceFixture data; test::MockHttpServer server; server.setResponse("ok"); EXPECT_TRUE(server.start());
    EXPECT_TRUE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir));
    EXPECT_TRUE(server.hit(0).body.find("x-instance-token")==std::string::npos);
    std::ofstream(data.dir/L"singleton-instance.json")<<"{broken";
    std::string diagnostic;
    EXPECT_FALSE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir,&diagnostic));
    EXPECT_STREQ(diagnostic,"window.record_invalid"); EXPECT_EQ(server.hits(),1u);
    data.write(server.port(),"bad\r\nheader");
    EXPECT_FALSE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir)); EXPECT_EQ(server.hits(),1u);
    const uint16_t unowned=server.port()==65535?1:static_cast<uint16_t>(server.port()+1);
    data.write(unowned,"do-not-send");
    EXPECT_FALSE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir,&diagnostic));
    EXPECT_STREQ(diagnostic,"window.record_owner"); EXPECT_EQ(server.hits(),1u);
}

APS_TEST(verge_official, rejected_activation_never_retries_or_follows_redirect) {
    for(const unsigned status:{302u,401u,403u,404u,503u}) {
        InstanceFixture data; test::MockHttpServer server,redirect;
        server.setResponse("ok"); redirect.setResponse("ok"); EXPECT_TRUE(redirect.start());
        server.setStatus(status,"Location: http://127.0.0.1:"+std::to_string(redirect.port())+"/commands/visible\r\n");
        EXPECT_TRUE(server.start()); data.write(server.port(),"private-value"); std::string diagnostic;
        EXPECT_FALSE(requestOfficialVergeWindow(GetCurrentProcessId(),data.dir,&diagnostic));
        EXPECT_STREQ(diagnostic,"window.http_"+std::to_string(status));
        EXPECT_TRUE(diagnostic.find("private-value")==std::string::npos);
        EXPECT_EQ(server.hits(),1u); EXPECT_EQ(redirect.hits(),0u);
    }
}

APS_TEST(verge_official, visible_window_bypasses_an_unknown_activation_protocol) {
    InstanceFixture data; std::ofstream(data.dir/L"singleton-instance.json")<<"future unsupported format";
    test::MockHttpServer server; EXPECT_TRUE(server.start());
    HWND window=CreateWindowW(L"STATIC",L"Clash Verge - compatibility fixture",WS_OVERLAPPEDWINDOW,
        0,0,100,100,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    EXPECT_TRUE(window!=nullptr); ShowWindow(window,SW_SHOWNOACTIVATE);
    std::string diagnostic;
    EXPECT_EQ(ensureOfficialVergeWindow(GetCurrentProcessId(),data.dir,{},&diagnostic),reinterpret_cast<uintptr_t>(window));
    EXPECT_TRUE(diagnostic.empty()); EXPECT_EQ(server.hits(),0u);
    DestroyWindow(window);
}

APS_TEST(verge_official, modern_logs_do_not_require_removed_start_but_cannot_prove_apply) {
    VergeUpdateEvidence e;e.uid="R";
    e.consume("[Config] [订阅更新] 直接更新失败: status 403 Forbidden，尝试使用Clash代理更新");
    EXPECT_FALSE(e.failed);
    e.consume("[Config] [订阅更新] 使用 Clash代理 更新订阅配置成功");
    EXPECT_TRUE(e.downloaded); EXPECT_FALSE(e.started); EXPECT_FALSE(e.applied);
    e.consume("[Validate] 配置与上次通过验证的字节一致，跳过内核检查"); EXPECT_FALSE(e.applied);
    e.consume("[Config] [订阅更新] 更新失败: 订阅已保存，但未能确认已应用到内核");
    EXPECT_TRUE(e.failed);
}

APS_TEST(verge_official, save_evidence_needs_same_uid_new_timestamp_and_file_write) {
    std::vector<VergeProfile> before{{"R","Target","R.yaml","100",true},{"X","Other","X.yaml","90",true}};
    auto now=before;
    auto check=[&](bool file){return verifyVergeProfileChange("R","R",before,"R",now,file);};
    EXPECT_TRUE(check(true)==VergeSavedState::Unchanged);
    now[0].updated="101"; EXPECT_TRUE(check(false)==VergeSavedState::Unchanged);
    EXPECT_TRUE(check(true)==VergeSavedState::Saved);
    now[0].updated="99"; EXPECT_TRUE(check(true)==VergeSavedState::Unchanged);
    now[0].updated="101oops"; EXPECT_TRUE(check(true)==VergeSavedState::Unchanged);
    now[0].updated="101"; now[1].updated="91"; EXPECT_TRUE(check(true)==VergeSavedState::Conflict);
    now=before;now[0].file="other.yaml"; EXPECT_TRUE(check(true)==VergeSavedState::Conflict);
    now=before;now[0].name="Edited"; EXPECT_TRUE(check(true)==VergeSavedState::Conflict);
    now=before;now.pop_back(); EXPECT_TRUE(check(true)==VergeSavedState::Conflict);
    now=before;now[1]=now[0]; EXPECT_TRUE(check(true)==VergeSavedState::Conflict);
    now=before; EXPECT_TRUE(verifyVergeProfileChange("R","R",before,"X",now,true)==VergeSavedState::Conflict);
}

int main(int argc, char** argv) {
    if(!net::initWinsock())return 2;
    struct WinsockCleanup { ~WinsockCleanup(){net::cleanupWinsock();} } winsockCleanup;
    if(argc==5 && std::string(argv[1])=="--inspect-live") {
        DiscoveredKernel kernel;kernel.pid=static_cast<uint32_t>(std::stoul(argv[2]));
        kernel.socksPort=static_cast<uint16_t>(std::stoul(argv[3]));kernel.apiPipe=argv[4];
        uint32_t clientPid=0;std::filesystem::path dir;std::string error;
        const bool paired=resolveOfficialVergeClient(kernel,clientPid,dir,error);
        auto result=json::Value::makeObject();result.set("paired",paired);result.set("client_pid",clientPid);
        result.set("diagnostic",error);
        if(paired) {
            auto group=ClashApiClient("127.0.0.1",0,"",kernel.apiPipe,kernel.pid).currentSelectorGroup(&error,1500);
            if(group) {
                result.set("group",group->name);result.set("node",group->now);
                result.set("region",region::detectNodeRegion(group->now));
                result.set("members",static_cast<uint32_t>(group->nodes.size()));
            } else result.set("selector_diagnostic",error);
        }
        result.set("scope","read-only controller identity and routing metadata; no delay test, refresh, window activation or selection");
        std::printf("%s\n",result.dump().c_str());return paired?0:1;
    }
    if(argc==4 && std::string(argv[1])=="--verify-window") {
        std::string diagnostic;
        const bool ok=requestOfficialVergeWindow(static_cast<uint32_t>(std::stoul(argv[2])),
                                                std::filesystem::path(utf8ToWide(argv[3])),&diagnostic);
        std::printf("window=%s diagnostic=%s\n",ok?"confirmed":"unconfirmed",diagnostic.c_str());
        return ok?0:1;
    }
    if (argc == 3 && std::string(argv[1]) == "--interop") {
        const auto controller = "\\\\.\\pipe\\aps-rust-interop-" + std::to_string(GetCurrentProcessId());
        std::wstring command = L"\"" + utf8ToWide(argv[2]) + L"\" " + utf8ToWide(controller);
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)) return 2;
        CloseHandle(process.hThread);
        bool ready = false;
        for (int i=0; i<60 && !ready; ++i) {
            ready = WaitNamedPipeW(utf8ToWide(controller + ".aps-profile-v1").c_str(),20) != FALSE;
            if (!ready) Sleep(25);
        }
        EXPECT_TRUE(ready);
        DiscoveredKernel kernel; kernel.pid = process.dwProcessId; kernel.apiPipe = controller;
        VergeSubscriptionTicket ticket; std::string error;
        const bool prepared = prepareVergeSubscription(kernel,ticket,error);
        EXPECT_TRUE(prepared);
        if (prepared) {
            EXPECT_EQ(ticket.clientPid,process.dwProcessId);
            std::printf("Interop request ID=%s identity=%s\n", ticket.requestId.c_str(), ticket.identity.dump().c_str());
            auto state = advanceVergeSubscription(ticket,error);
            for (int i=0; i<40 && (state == VergeRefreshState::Running || state == VergeRefreshState::Unconfirmed); ++i) {
                Sleep(25); state = advanceVergeSubscription(ticket,error);
            }
            if (state != VergeRefreshState::Succeeded) std::printf("Interop state=%d error=%s\n", static_cast<int>(state), error.c_str());
            EXPECT_TRUE(state == VergeRefreshState::Succeeded);
        }
        EXPECT_EQ(WaitForSingleObject(process.hProcess,10000),static_cast<DWORD>(WAIT_OBJECT_0));
        CloseHandle(process.hProcess);
        return aps::test::failureCount() ? 1 : 0;
    }
    return aps::test::runAll("test_verge_subscription");
}
