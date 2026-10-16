// Exercise background refresh, show state and DPI paths with real child windows.
// Link-time doubles below replace the IPC, config and tray object files:
// this executable cannot contact a running engine or modify the user's data.
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

#include <memory>
#include <map>
#include <string>

#include "main_window.hpp"
#include "app.hpp"
#include "aps/string_util.hpp"
#include "mock_socks_server.hpp"
#include "testlib/appsw_test.h"

using namespace aps::gui;

namespace {
int clientConstructions = 0;
int mutations = 0;
int fixtureRuleCount = 1;
std::string fixtureRuleOutlet;
std::string lastTestRequestId;
const std::string snapshot = R"({
  "type":"STATS",
  "kernels":[{"id":"auto-test","name":"Offline test kernel","alive":true,"api_port":9090}],
  "outlets":[{"id":"auto-test","name":"Offline test kernel","api":true,"alive":true,"node":"Test node","latency_ms":42,"groups":["Test group"]}],
  "connections":[{"proc":"C:\\Test\\app.exe","dst_ip":"192.0.2.1","dst_port":443,"rule_id":"test-rule","outlet_id":"auto-test","bytes_up":100,"bytes_down":200,"duration_ms":1000}]
})";

bool rejectMutation() { ++mutations; return false; }

std::wstring textOf(HWND hwnd) {
    wchar_t text[512]{};
    GetWindowTextW(hwnd, text, 512);
    return text;
}

HWND findControl(HWND parent, int id) {
    if (HWND control = GetDlgItem(parent, id)) return control;
    for (HWND child = GetWindow(parent, GW_CHILD); child;
         child = GetWindow(child, GW_HWNDNEXT)) {
        if (HWND control = findControl(child, id)) return control;
    }
    return nullptr;
}

HWND findText(HWND parent, const std::wstring& wanted) {
    for (HWND child = GetWindow(parent, GW_CHILD); child;
         child = GetWindow(child, GW_HWNDNEXT)) {
        if (textOf(child) == wanted) return child;
        if (HWND label = findText(child, wanted)) return label;
    }
    return nullptr;
}

bool hasText(HWND parent, const std::wstring& wanted) {
    return findText(parent, wanted) != nullptr;
}

RECT bounds(HWND child) { RECT r{}; GetWindowRect(child, &r); return r; }

std::string manyKernelsSnapshot(bool differentNames = false) {
    aps::json::Value v;
    aps::json::Value::parse(snapshot, v, nullptr);
    auto kernels = *v.find("kernels");
    for (int i = 0; i < 30; ++i) {
        aps::json::Value k = aps::json::Value::makeObject();
        k.set("id", "auto-offline-" + std::to_string(i));
        k.set("name", differentNames ? "offline-core-" + std::to_string(i) + ".exe" : "verge-mihomo.exe");
        k.set("alive", false); k.set("seen", true); k.set("socks_port", 50000 + i);
        kernels.append(k);
    }
    v.set("kernels", kernels);
    auto connections = aps::json::Value::makeArray();
    for (int i = 0; i < 50; ++i) {
        auto flow = v.find("connections")->at(0);
        flow.set("app_port", 30000 + i);
        flow.set("pid", 100);
        flow.set("bytes_up", 2048 * i);
        connections.append(flow);
    }
    v.set("connections", connections);
    return v.dump();
}

void actualProxy(MainWindow& w, int port) {
    w.onPipeState(true);
    w.onPipeMessage("{\"type\":\"STATUS\",\"state\":\"RUNNING\",\"effective_proxy\":{"
        "\"id\":\"auto-test\",\"host\":\"127.0.0.1\",\"name\":\"Clash Verge\",\"port\":" +
        std::to_string(port) + "}}");
}

void finishProbe(HWND hwnd) {
    for (int i = 0; i < 800 && !IsWindowEnabled(findControl(hwnd, 109)); ++i) {
        MSG msg{};
        while (PeekMessageW(&msg, hwnd, WM_APP_PROXY_TEST, WM_APP_PROXY_TEST, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(5);
    }
}

struct WindowFixture {
    std::unique_ptr<MainWindow> window;
    WindowFixture() {
        INITCOMMONCONTROLSEX controls{sizeof(controls),
                                      ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
        InitCommonControlsEx(&controls);
        mutations = 0;
        clientConstructions = 0;
        window.reset(MainWindow::create(GetModuleHandleW(nullptr)));
        SetWindowTextW(window->hwnd(), L"APS offline DPI regression test");
        window->onPipeMessage(snapshot);
    }
    ~WindowFixture() { DestroyWindow(window->hwnd()); }
    HWND hwnd() const { return window->hwnd(); }
    void dpiChanged() {
        RECT suggested{};
        GetWindowRect(hwnd(), &suggested);
        const UINT dpi = GetDpiForWindow(hwnd());
        SendMessageW(hwnd(), WM_DPICHANGED, MAKELONG(dpi, dpi),
                     reinterpret_cast<LPARAM>(&suggested));
    }
};

struct VisibilityTrace {
    HWND hwnd;
    int visibleStyleChanges = 0;
    explicit VisibilityTrace(HWND window) : hwnd(window) {
        SetWindowSubclass(hwnd, observe, 1, reinterpret_cast<DWORD_PTR>(this));
    }
    ~VisibilityTrace() { RemoveWindowSubclass(hwnd, observe, 1); }
    static LRESULT CALLBACK observe(HWND wnd, UINT msg, WPARAM wp, LPARAM lp,
                                    UINT_PTR, DWORD_PTR context) {
        auto* self = reinterpret_cast<VisibilityTrace*>(context);
        const auto visibleBefore = GetWindowLongPtrW(wnd, GWL_STYLE) & WS_VISIBLE;
        const auto result = DefSubclassProc(wnd, msg, wp, lp);
        if (msg == WM_SETREDRAW &&
            visibleBefore != (GetWindowLongPtrW(wnd, GWL_STYLE) & WS_VISIBLE))
            ++self->visibleStyleChanges;
        return result;
    }
};

struct RefreshTrace {
    HWND root;
    std::map<HWND, RECT> rectangles;
    int geometryChanges = 0;
    int textWrites = 0;
    int backgroundErases = 0;
    int fullBackgroundErases = 0;
    explicit RefreshTrace(HWND window) : root(window) {
        watch(root);
        for(HWND child=GetWindow(root,GW_CHILD);child;child=GetWindow(child,GW_HWNDNEXT))
            watch(child);
        HWND pane=findControl(root,131);
        for(HWND child=GetWindow(pane,GW_CHILD);child;child=GetWindow(child,GW_HWNDNEXT))
            watch(child);
    }
    void watch(HWND child) {
        rectangles[child]=bounds(child);
        SetWindowSubclass(child,observe,2,reinterpret_cast<DWORD_PTR>(this));
    }
    ~RefreshTrace() {
        for(const auto& entry:rectangles)RemoveWindowSubclass(entry.first,observe,2);
    }
    static LRESULT CALLBACK observe(HWND wnd,UINT msg,WPARAM wp,LPARAM lp,
                                    UINT_PTR,DWORD_PTR context) {
        auto* self=reinterpret_cast<RefreshTrace*>(context);
        if(msg==WM_WINDOWPOSCHANGED) {
            const RECT current=bounds(wnd);
            auto& previous=self->rectangles[wnd];
            if(!EqualRect(&current,&previous))++self->geometryChanges;
            previous=current;
        }
        if(msg==WM_SETTEXT)++self->textWrites;
        if(msg==WM_ERASEBKGND&&wnd==self->root) {
            ++self->backgroundErases;
            RECT clip{},client{};
            GetClipBox(reinterpret_cast<HDC>(wp),&clip);
            GetClientRect(wnd,&client);
            if(EqualRect(&clip,&client))++self->fullBackgroundErases;
        }
        return DefSubclassProc(wnd,msg,wp,lp);
    }
};

void flushPaint(HWND window) {
    RedrawWindow(window,nullptr,nullptr,RDW_UPDATENOW|RDW_ALLCHILDREN);
}
}  // namespace

// All externally mutating boundaries are replaced for this test target only.
namespace aps::gui {
EngineClient::EngineClient(Callbacks cbs) : cbs_(std::move(cbs)) {
    ++clientConstructions;
}
bool EngineClient::ensureEngineRunning() { return rejectMutation(); }
void EngineClient::connectPipe() {}
void EngineClient::disconnectPipe() {}
bool EngineClient::sendStop() { return rejectMutation(); }
bool EngineClient::sendReload() { return rejectMutation(); }
bool EngineClient::sendFlush(const std::string&) { return rejectMutation(); }
bool EngineClient::sendSetEnabled(bool) { return rejectMutation(); }
bool EngineClient::sendNodeSwitch(const std::string&, const std::string& requestId) {
    ++mutations; lastTestRequestId=requestId; return true;
}
bool EngineClient::sendSetVisible(bool) { return true; }
bool EngineClient::sendSubRefresh() { return rejectMutation(); }

GuiConfigState loadOrCreateConfig() {
    GuiConfigState state;
    state.cfg = Config::makeDefault();
    state.cfg.routing.autoOutletId = "auto-test";
    state.cfg.nodeMonitor.nodeClasses = {"GROUP:Test group"};
    Outlet outlet;
    outlet.id = "manual-test";
    outlet.name = "Manual test outlet";
    state.cfg.outlets.push_back(outlet);
    Rule rule;
    rule.id = "test-rule";
    rule.name = "Test rule";
    rule.path = "C:\\Test\\app.exe";
    rule.outlet = fixtureRuleOutlet;
    for (int i = 0; i < fixtureRuleCount; ++i) {
        if (i) rule.id = "test-rule-" + std::to_string(i);
        state.cfg.rules.push_back(rule);
    }
    state.loaded = true;
    return state;
}
bool saveConfig(GuiConfigState&, std::string*) { return rejectMutation(); }
bool upsertRule(GuiConfigState&, const Rule&, std::string*) { return rejectMutation(); }
bool deleteRule(GuiConfigState&, const std::string&, std::string*) { return rejectMutation(); }
std::optional<Rule> findRule(const GuiConfigState&, const std::string&) { return {}; }
bool setAutostart(bool) { return rejectMutation(); }
bool autostartEnabled() { return false; }

TrayIcon::~TrayIcon() = default;
bool TrayIcon::create(HWND) { return true; }
bool TrayIcon::restoreAfterTaskbarRestart() { return true; }
void TrayIcon::remove() {}
void TrayIcon::setTooltip(const wchar_t*) {}
void TrayIcon::showBalloon(const wchar_t*, const wchar_t*) {}
int TrayIcon::showMenu() { return 0; }
}  // namespace aps::gui

APS_TEST(mainwindow, background_layout_preserves_top_level_visibility) {
    WindowFixture f;
    VisibilityTrace trace(f.hwnd());
    for (int tick = 0; tick < 5; ++tick) {
        f.window->onPipeMessage(tick % 2 ? snapshot : manyKernelsSnapshot());
        EXPECT_TRUE(IsWindowVisible(f.hwnd()) != FALSE);
        EXPECT_FALSE(IsIconic(f.hwnd()) != FALSE);
    }
    // A repaint must not remove/re-add the taskbar window's WS_VISIBLE bit.
    EXPECT_EQ(trace.visibleStyleChanges, 0);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, live_counters_do_not_move_scrolled_controls_or_erase_whole_window) {
    WindowFixture f;
    aps::json::Value value;
    aps::json::Value::parse(snapshot,value,nullptr);
    f.window->onPipeMessage(value.dump());
    SetWindowPos(f.hwnd(),nullptr,0,0,Scaled(740),Scaled(540),SWP_NOMOVE|SWP_NOZORDER);
    SendMessageW(f.hwnd(),WM_HSCROLL,SB_BOTTOM,0);
    SendMessageW(f.hwnd(),WM_VSCROLL,SB_BOTTOM,0);
    flushPaint(f.hwnd());
    RefreshTrace trace(f.hwnd());
    for(int tick=0;tick<10;++tick) {
        auto flow=value.find("connections")->at(0);
        flow.set("bytes_down",1000+tick);
        flow.set("duration_ms",1000*(tick+1));
        auto connections=aps::json::Value::makeArray();
        connections.append(flow);
        value.set("connections",connections);
        f.window->onPipeMessage(value.dump());
        flushPaint(f.hwnd());
    }
    std::printf("    10 scrolled refreshes: moves=%d parent erases=%d full-client erases=%d\n",
                trace.geometryChanges,trace.backgroundErases,trace.fullBackgroundErases);
    EXPECT_EQ(trace.geometryChanges,0);
    EXPECT_EQ(trace.backgroundErases,0);
    wchar_t duration[64]{},download[64]{};
    ListView_GetItemText(findControl(f.hwnd(),1002),0,4,duration,64);
    ListView_GetItemText(findControl(f.hwnd(),1002),0,6,download,64);
    EXPECT_TRUE(std::wstring(duration)==L"10 秒");
    EXPECT_TRUE(std::wstring(download)==L"1009 B");
    EXPECT_EQ(mutations,0);
}

APS_TEST(mainwindow, unchanged_node_status_has_no_placeholder_text_roundtrip) {
    WindowFixture f;
    const std::string noApi=R"({"type":"STATS","kernels":[{"id":"auto-test","name":"core.exe","alive":true,"seen":true,"has_api":false}],"outlets":[]})";
    f.window->onPipeMessage(noApi);
    flushPaint(f.hwnd());
    RefreshTrace trace(f.hwnd());
    for(int tick=0;tick<10;++tick) {
        f.window->onPipeMessage(noApi);
        flushPaint(f.hwnd());
    }
    std::printf("    10 unchanged node refreshes: text writes=%d moves=%d\n",
                trace.textWrites,trace.geometryChanges);
    EXPECT_EQ(trace.textWrites,0);
    EXPECT_EQ(trace.geometryChanges,0);
    EXPECT_EQ(trace.backgroundErases,0);
    EXPECT_TRUE(hasText(f.hwnd(),L"内核运行中；节点控制器未识别"));
    EXPECT_EQ(mutations,0);
}

APS_TEST(mainwindow, wrapped_nodes_stay_still_after_resize_dpi_and_inner_scroll) {
    WindowFixture f;
    aps::json::Value value;
    aps::json::Value::parse(snapshot,value,nullptr);
    std::string warning;
    for(int i=0;i<16;++i)warning+="Wrapped route warning preserves the selected outlet and live connection. ";
    auto outlet=value.find("outlets")->at(0);
    outlet.set("routing_warning",warning);
    for(int width:{740,1100,760}) {
        auto outlets=aps::json::Value::makeArray();outlets.append(outlet);
        value.set("outlets",outlets);
        f.window->onPipeMessage(value.dump());
        SetWindowPos(f.hwnd(),nullptr,0,0,Scaled(width),Scaled(540),SWP_NOMOVE|SWP_NOZORDER);
        SendMessageW(f.hwnd(),WM_VSCROLL,SB_BOTTOM,0);
        SendMessageW(f.hwnd(),WM_HSCROLL,SB_BOTTOM,0);
        HWND pane=findControl(f.hwnd(),131);
        SendMessageW(pane,WM_VSCROLL,SB_BOTTOM,0);
        SCROLLINFO before{sizeof(before),SIF_POS};GetScrollInfo(pane,SB_VERT,&before);
        EXPECT_GT(before.nPos,0);
        flushPaint(f.hwnd());
        {
            RefreshTrace trace(f.hwnd());
            for(int tick=0;tick<10;++tick) {
                auto changed=outlet;changed.set("latency_ms",100+tick);
                auto fresh=aps::json::Value::makeArray();fresh.append(changed);
                value.set("outlets",fresh);
                f.window->onPipeMessage(value.dump());
                flushPaint(f.hwnd());
            }
            std::printf("    width %d: moves=%d full-client erases=%d\n",
                        width,trace.geometryChanges,trace.fullBackgroundErases);
            EXPECT_EQ(trace.geometryChanges,0);
            EXPECT_EQ(trace.fullBackgroundErases,0);
            EXPECT_TRUE(hasText(f.hwnd(),L"Test node  109ms"));
        }
        SCROLLINFO after{sizeof(after),SIF_POS};GetScrollInfo(pane,SB_VERT,&after);
        EXPECT_EQ(after.nPos,before.nPos);
        f.dpiChanged();
    }
    EXPECT_EQ(mutations,0);
}

APS_TEST(mainwindow, minimized_window_stays_minimized_during_background_updates) {
    WindowFixture f;
    ShowWindow(f.hwnd(), SW_SHOWMINNOACTIVE);
    EXPECT_TRUE(IsIconic(f.hwnd()) != FALSE);
    VisibilityTrace trace(f.hwnd());
    for (int tick = 0; tick < 5; ++tick) {
        f.window->onPipeMessage(tick % 2 ? snapshot : manyKernelsSnapshot());
        f.window->onPipeState(false);
        f.window->onPipeState(true);
        f.window->onPipeMessage(R"({"type":"STATUS","state":"RUNNING"})");
        EXPECT_TRUE(IsWindowVisible(f.hwnd()) != FALSE);
        EXPECT_TRUE(IsIconic(f.hwnd()) != FALSE);
    }
    EXPECT_EQ(trace.visibleStyleChanges, 0);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, tray_hidden_window_stays_hidden_during_background_updates) {
    WindowFixture f;
    ShowWindow(f.hwnd(), SW_HIDE);
    VisibilityTrace trace(f.hwnd());
    for (int tick = 0; tick < 5; ++tick) {
        f.window->onPipeMessage(tick % 2 ? snapshot : manyKernelsSnapshot());
        f.window->onPipeState(false);
        f.window->onPipeState(true);
        f.dpiChanged();
        EXPECT_FALSE(IsWindowVisible(f.hwnd()) != FALSE);
    }
    EXPECT_EQ(trace.visibleStyleChanges, 0);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, explicit_show_request_restores_the_window) {
    WindowFixture f;
    for (int state : {SW_SHOWMINNOACTIVE, SW_HIDE}) {
        ShowWindow(f.hwnd(), state);
        SendMessageW(f.hwnd(), WM_APP_SHOW, 0, 0);
        EXPECT_TRUE(IsWindowVisible(f.hwnd()) != FALSE);
        EXPECT_FALSE(IsIconic(f.hwnd()) != FALSE);
    }
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, minimized_connections_refresh_on_the_first_restored_snapshot) {
    WindowFixture f;
    HWND connections = findControl(f.hwnd(), 1002);
    EXPECT_EQ(ListView_GetItemCount(connections), 1);
    ShowWindow(f.hwnd(), SW_SHOWMINNOACTIVE);
    const auto changed = manyKernelsSnapshot();
    f.window->onPipeMessage(changed);
    EXPECT_EQ(ListView_GetItemCount(connections), 1);
    SendMessageW(f.hwnd(), WM_APP_SHOW, 0, 0);
    f.window->onPipeMessage(changed); // identical to the skipped payload
    EXPECT_EQ(ListView_GetItemCount(connections), 50);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, dpi_rebuild_preserves_node_rows_and_selection) {
    WindowFixture f;
    EXPECT_TRUE(hasText(f.hwnd(), L"Test node  42ms"));
    f.window->onPipeMessage(R"({"type":"STATUS","sub_refresh":"running"})");
    for (int cycle = 0; cycle < 3; ++cycle) {
        f.dpiChanged();
        for (int id = 2000; id < 2003; ++id) {
            HWND button = findControl(f.hwnd(), id);
            EXPECT_TRUE(button != nullptr);
            EXPECT_TRUE(IsWindowVisible(button) != FALSE);
            RECT bounds{};
            GetWindowRect(button, &bounds);
            EXPECT_GT(bounds.right - bounds.left, 0);
            EXPECT_GT(bounds.bottom - bounds.top, 0);
        }
        EXPECT_EQ(SendMessageW(findControl(f.hwnd(), 2002), BM_GETCHECK, 0, 0),
                  LRESULT{BST_CHECKED});
        EXPECT_TRUE(textOf(findControl(f.hwnd(), 124)) == L"分组:Test group");
        EXPECT_TRUE(textOf(findControl(f.hwnd(), 126)) == L"刷新中…");
        f.window->onPipeMessage(snapshot);
        EXPECT_TRUE(hasText(f.hwnd(), L"Test node  42ms"));
        EXPECT_EQ(ListView_GetItemCount(findControl(f.hwnd(), 1001)), 1);
    }
    EXPECT_EQ(clientConstructions, 1);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, identical_stats_repopulate_connections_after_dpi_rebuild) {
    WindowFixture f;
    EXPECT_EQ(ListView_GetItemCount(findControl(f.hwnd(), 1002)), 1);
    f.dpiChanged();
    f.window->onPipeMessage(snapshot);  // byte-for-byte identical engine push
    EXPECT_EQ(ListView_GetItemCount(findControl(f.hwnd(), 1002)), 1);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, unchanged_outlets_repair_missing_controls) {
    WindowFixture f;
    EXPECT_TRUE(DestroyWindow(findControl(f.hwnd(), 2002)) != FALSE);
    f.window->onPipeMessage(snapshot);
    EXPECT_TRUE(findControl(f.hwnd(), 2002) != nullptr);
    EXPECT_TRUE(hasText(f.hwnd(), L"Test node  42ms"));
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, offline_kernels_fold_without_compressing_tables) {
    fixtureRuleCount = 40;
    WindowFixture f;
    fixtureRuleCount = 1;
    f.window->onPipeMessage(manyKernelsSnapshot(true));
    SetWindowPos(f.hwnd(), nullptr, 0, 0, Scaled(740), Scaled(540), SWP_NOMOVE | SWP_NOZORDER);
    HWND rules = findControl(f.hwnd(), 1001), conns = findControl(f.hwnd(), 1002);
    EXPECT_TRUE(findControl(f.hwnd(), 2002) != nullptr);
    EXPECT_TRUE(findControl(f.hwnd(), 2003) == nullptr);
    EXPECT_TRUE(textOf(findControl(f.hwnd(), 128)).find(L"30") != std::wstring::npos);
    for (int expanded = 0; expanded < 2; ++expanded) {
        RECT r = bounds(rules), c = bounds(conns);
        EXPECT_GE(r.bottom - r.top, Scaled(140));
        EXPECT_GE(c.bottom - c.top, Scaled(140));
        EXPECT_LT(r.bottom, c.top);
        EXPECT_LT(c.bottom, bounds(findControl(f.hwnd(), 114)).top);
        SCROLLINFO si{sizeof(si), SIF_ALL};
        GetScrollInfo(rules, SB_VERT, &si); EXPECT_GT(si.nMax, static_cast<int>(si.nPage));
        GetScrollInfo(conns, SB_VERT, &si); EXPECT_GT(si.nMax, static_cast<int>(si.nPage));
        GetScrollInfo(f.hwnd(), SB_VERT, &si); EXPECT_GT(si.nMax, static_cast<int>(si.nPage));
        SendMessageW(f.hwnd(), WM_COMMAND, 128, 0);
    }
    EXPECT_TRUE(findControl(f.hwnd(), 2003) == nullptr);
    const int oldTop = bounds(rules).top;
    SendMessageW(f.hwnd(), WM_VSCROLL, SB_PAGEDOWN, 0);
    EXPECT_LT(bounds(rules).top, oldTop);
    SendMessageW(f.hwnd(), WM_VSCROLL, SB_TOP, 0);
    EXPECT_EQ(bounds(rules).top, oldTop);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, offline_history_keeps_one_name_without_old_ports) {
    WindowFixture f;
    f.window->onPipeMessage(manyKernelsSnapshot());
    EXPECT_TRUE(textOf(findControl(f.hwnd(), 128)) == L"展开未启动内核（1）");
    SendMessageW(f.hwnd(), WM_COMMAND, 128, 0);
    EXPECT_TRUE(hasText(f.hwnd(), L"verge-mihomo.exe"));
    EXPECT_FALSE(hasText(f.hwnd(), L"verge-mihomo.exe:50000"));
    EXPECT_FALSE(hasText(f.hwnd(), L"verge-mihomo.exe:50029"));
    EXPECT_TRUE(findControl(f.hwnd(), 2003) != nullptr);
    EXPECT_TRUE(findControl(f.hwnd(), 2004) == nullptr);
    f.window->onPipeMessage(R"({"type":"STATS","kernels":[
        {"id":"auto-test","name":"verge-mihomo.exe","alive":true,"seen":true,"socks_port":60000},
        {"id":"auto-other","name":"verge-mihomo.exe","alive":true,"seen":true,"socks_port":60001},
        {"id":"auto-old","name":"verge-mihomo.exe","alive":false,"seen":true,"socks_port":50000}
    ],"outlets":[]})");
    EXPECT_TRUE(hasText(f.hwnd(), L"verge-mihomo.exe:60000"));
    EXPECT_TRUE(hasText(f.hwnd(), L"verge-mihomo.exe:60001"));
    EXPECT_FALSE(hasText(f.hwnd(), L"verge-mihomo.exe"));
    EXPECT_TRUE(findControl(f.hwnd(), 2003) != nullptr);
    EXPECT_TRUE(findControl(f.hwnd(), 2004) == nullptr);
    // An activated offline ID remains visible beside another live instance.
    f.window->onPipeMessage(R"({"type":"STATS","kernels":[
        {"id":"auto-test","name":"verge-mihomo.exe","alive":false,"seen":true,"socks_port":60000},
        {"id":"auto-other","name":"verge-mihomo.exe","alive":true,"seen":true,"socks_port":60001}
    ],"outlets":[]})");
    EXPECT_TRUE(hasText(f.hwnd(), L"verge-mihomo.exe"));
    EXPECT_TRUE(hasText(f.hwnd(), L"verge-mihomo.exe:60001"));
    EXPECT_EQ(SendMessageW(findControl(f.hwnd(), 2002), BM_GETCHECK, 0, 0), LRESULT{BST_CHECKED});
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, long_node_details_wrap_and_scroll_inside_the_node_pane) {
    WindowFixture f;
    aps::json::Value v;
    aps::json::Value::parse(snapshot, v, nullptr);
    auto outlets = aps::json::Value::makeArray();
    std::string detail;
    for (int i = 0; i < 14; ++i) detail += "规则模式按转发进程分流，目标服务的代理链待核对。";
    for (const auto& id : {"__default__", "manual-test", "auto-test"}) {
        auto o = aps::json::Value::makeObject();
        o.set("id", id); o.set("api", true); o.set("alive", true);
        o.set("node", "Test node"); o.set("latency_ms", 42);
        o.set("runtime_mode", "rule"); o.set("group", "较长的节点策略分组名称");
        o.set("routing_warning", std::string(id) + detail);
        outlets.append(o);
    }
    v.set("outlets", outlets);
    f.window->onPipeMessage(v.dump());
    SetWindowPos(f.hwnd(), nullptr, 0, 0, Scaled(740), Scaled(540), SWP_NOMOVE | SWP_NOZORDER);
    for (int dpiCycle = 0; dpiCycle < 2; ++dpiCycle) {
        HWND pane = findControl(f.hwnd(), 131);
        EXPECT_TRUE(pane != nullptr);
        EXPECT_TRUE((GetWindowLongPtrW(pane, GWL_STYLE) & WS_VSCROLL) != 0);
        EXPECT_TRUE((GetWindowLongPtrW(pane, GWL_STYLE) & WS_CLIPCHILDREN) != 0);
        HWND firstDetail = findText(pane, L"__default__" + aps::utf8ToWide(detail));
        HWND secondName = findText(pane, L"Manual test outlet");
        EXPECT_TRUE(firstDetail != nullptr);
        EXPECT_TRUE(secondName != nullptr);
        const RECT d = bounds(firstDetail), n = bounds(secondName);
        EXPECT_GT(d.bottom - d.top, Scaled(40));
        EXPECT_LE(d.bottom, n.top); // no overlap after wrapping
        EXPECT_LT(d.right, bounds(findControl(f.hwnd(), 2000)).left);
        SCROLLINFO si{sizeof(si), SIF_ALL};
        GetScrollInfo(pane, SB_VERT, &si);
        EXPECT_GT(si.nMax + 1, static_cast<int>(si.nPage));
        const int tableTop = bounds(findControl(f.hwnd(), 1001)).top;
        const int detailTop = d.top;
        SendMessageW(pane, WM_VSCROLL, SB_BOTTOM, 0);
        GetScrollInfo(pane, SB_VERT, &si);
        EXPECT_EQ(si.nPos, si.nMax - static_cast<int>(si.nPage) + 1);
        EXPECT_LT(bounds(firstDetail).top, detailTop);
        EXPECT_EQ(bounds(findControl(f.hwnd(), 1001)).top, tableTop);
        SendMessageW(pane, WM_MOUSEWHEEL, MAKEWPARAM(0, WHEEL_DELTA), 0);
        SCROLLINFO after{sizeof(after), SIF_ALL}; GetScrollInfo(pane, SB_VERT, &after);
        EXPECT_LT(after.nPos, si.nPos);
        SendMessageW(pane, WM_VSCROLL, SB_TOP, 0);
        EXPECT_EQ(bounds(firstDetail).top, detailTop);
        f.dpiChanged();
        EXPECT_TRUE(findText(findControl(f.hwnd(), 131), L"__default__" + aps::utf8ToWide(detail)) != nullptr);
        f.window->onPipeMessage(v.dump());
    }
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, explicitly_bound_offline_instance_remains_visible) {
    fixtureRuleOutlet = "auto-bound";
    WindowFixture f;
    fixtureRuleOutlet.clear();
    f.window->onPipeMessage(R"({"type":"STATS","kernels":[
        {"id":"auto-test","name":"Test core","alive":true,"seen":true,"socks_port":50000},
        {"id":"auto-bound","name":"same-core.exe","alive":false,"seen":true,"socks_port":50001},
        {"id":"auto-live","name":"same-core.exe","alive":true,"seen":true,"socks_port":60001},
        {"id":"auto-old","name":"same-core.exe","alive":false,"seen":true,"socks_port":50002}
    ],"outlets":[]})");
    EXPECT_TRUE(hasText(f.hwnd(), L"same-core.exe"));
    EXPECT_TRUE(hasText(f.hwnd(), L"same-core.exe:60001"));
    EXPECT_FALSE(hasText(f.hwnd(), L"same-core.exe:50001"));
    EXPECT_TRUE(findControl(f.hwnd(), 2004) != nullptr);
    EXPECT_TRUE(findControl(f.hwnd(), 2005) == nullptr);
    EXPECT_EQ(mutations, 0);
}

APS_TEST(mainwindow, test_uses_runtime_port_without_reloading_manual_settings) {
    aps::net::initWinsock();
    aps::test::MockSocks5Server server;
    EXPECT_TRUE(server.start());
    WindowFixture f;
    actualProxy(*f.window, server.port());
    SendMessageW(f.hwnd(), WM_COMMAND, 109, 0);
    finishProbe(f.hwnd());
    auto result = textOf(findControl(f.hwnd(), 110));
    EXPECT_TRUE(result.find(std::to_wstring(server.port())) != std::wstring::npos);
    EXPECT_TRUE(result.find(L"握手正常") != std::wstring::npos);
    EXPECT_TRUE(textOf(findControl(f.hwnd(), 106)) == L"7891");
    EXPECT_EQ(mutations, 0);
    // Result belongs to its captured endpoint, even when it arrives after a switch.
    SendMessageW(f.hwnd(), WM_COMMAND, 109, 0);
    actualProxy(*f.window, 2);
    finishProbe(f.hwnd());
    EXPECT_TRUE(textOf(findControl(f.hwnd(), 110)).empty());
    EXPECT_TRUE(textOf(findControl(f.hwnd(), 129)).find(L"127.0.0.1:2") != std::wstring::npos);
    f.window->onPipeState(false);
    EXPECT_TRUE(textOf(findControl(f.hwnd(), 129)).find(L"引擎未连接") != std::wstring::npos);
}

APS_TEST(mainwindow, socks_only_kernel_does_not_claim_endless_detection) {
    WindowFixture f;
    f.window->onPipeMessage(R"({"type":"STATS","kernels":[{"id":"auto-test","name":"core.exe","alive":true,"seen":true,"api_port":0,"has_api":false}],"outlets":[]})");
    EXPECT_TRUE(hasText(f.hwnd(), L"内核运行中；节点控制器未识别"));
}

APS_TEST(mainwindow, node_metadata_and_pending_test_ignore_stale_success) {
    WindowFixture f;
    f.window->onPipeState(true);
    f.window->onPipeMessage(R"({"type":"STATS","kernels":[{"id":"auto-test","name":"Test core","alive":true,"has_api":true}],"outlets":[{"id":"auto-test","api":true,"alive":true,"node":"日本-家宽-IEPL 01","latency_ms":42,"region":"JP","node_classes":["IEPL","RES"],"group":"Main route"}]})");
    EXPECT_TRUE(hasText(f.hwnd(),L"日本-家宽-IEPL 01  42ms"));
    EXPECT_TRUE(hasText(f.hwnd(),L"地区: 日本 · 类型: IEPL/家宽 · 策略组: Main route"));
    HWND active=nullptr;
    for(HWND child=GetWindow(findControl(f.hwnd(),131),GW_CHILD);child;child=GetWindow(child,GW_HWNDNEXT))
        if(textOf(child)==L"测试并连接" && SendMessageW(child,BM_GETCHECK,0,0)==BST_CHECKED)active=child;
    EXPECT_TRUE(active!=nullptr);
    if(!active)return;
    SendMessageW(GetParent(active),WM_COMMAND,GetDlgCtrlID(active),reinterpret_cast<LPARAM>(active));
    EXPECT_EQ(mutations,1);
    f.window->onPipeMessage(snapshot); // previous ALIVE does not finish this request
    EXPECT_TRUE(hasText(f.hwnd(),L"测量中…"));
    f.window->onPipeMessage(R"({"type":"STATS","outlets":[{"id":"auto-test","api":true,"alive":true,"node":"Other request","latency_ms":42,"switching":false,"test_request_id":"another-click"}]})");
    EXPECT_TRUE(hasText(f.hwnd(),L"测量中…"));
    EXPECT_FALSE(lastTestRequestId.empty());
    f.window->onPipeMessage("{\"type\":\"STATS\",\"outlets\":[{\"id\":\"auto-test\",\"api\":true,\"alive\":true,\"node\":\"Old node\",\"latency_ms\":42,\"switching\":true,\"test_request_id\":\""+lastTestRequestId+"\"}]}");
    f.window->onPipeMessage("{\"type\":\"STATS\",\"outlets\":[{\"id\":\"auto-test\",\"api\":true,\"alive\":true,\"node\":\"New node\",\"latency_ms\":25,\"switching\":false,\"selection_ok\":true,\"test_request_id\":\""+lastTestRequestId+"\"}]}");
    EXPECT_TRUE(hasText(f.hwnd(),L"New node  25ms"));
    EXPECT_EQ(mutations,1); // active outlet is not saved/reloaded on completion
}

APS_TEST(mainwindow, incident_routing_mode_and_business_warning_visible) {
    WindowFixture f;
    f.window->onPipeState(true);
    f.window->onPipeMessage(R"({"type":"STATS","outlets":[{"id":"auto-test","api":false,"alive":false,"runtime_mode":"direct","api_msg":"内核处于直连模式","routing_warning":"节点测速不代表目标服务可达"}]})");
    EXPECT_TRUE(hasText(f.hwnd(), L"内核处于直连模式"));
    EXPECT_TRUE(hasText(f.hwnd(), L"模式: direct"));
    EXPECT_TRUE(hasText(f.hwnd(), L"节点测速不代表目标服务可达"));
    f.window->onPipeMessage(R"({"type":"STATS","outlets":[{"id":"auto-test","api":true,"alive":true,"node":"Test node","runtime_mode":"rule","routing_warning":"规则模式按 APS 转发进程分流，目标服务的代理链待核对"}]})");
    EXPECT_TRUE(hasText(f.hwnd(), L"地区: 未知 · 类型: 未知 · 模式: rule"));
    EXPECT_TRUE(hasText(f.hwnd(), L"规则模式按 APS 转发进程分流，目标服务的代理链待核对"));
}

int main(int argc, char** argv) {
    SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if (argc > 1 && std::string(argv[1]) == "--preview") {
        fixtureRuleCount = 8;
        WindowFixture f;
        f.window->onPipeMessage(manyKernelsSnapshot());
        actualProxy(*f.window, 57364);
        SetWindowTextW(f.hwnd(), L"APS 1.2.11 离线界面预览（模拟数据，不连接引擎）");
        ShowWindow(f.hwnd(), SW_SHOW);
        const UINT_PTR timer = SetTimer(nullptr, 0, 1000, nullptr);
        int ticks = 0;
        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (!msg.hwnd && msg.message == WM_TIMER && msg.wParam == timer) {
                if (++ticks >= 180) break;
                f.window->onPipeMessage(manyKernelsSnapshot());
                actualProxy(*f.window, 57364);
            }
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        KillTimer(nullptr, timer);
        return 0;
    }
    return aps::test::runAll(nullptr);
}
