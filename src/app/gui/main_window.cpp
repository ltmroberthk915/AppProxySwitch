#include "main_window.hpp"

#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <rpc.h>

#include <atomic>
#include <algorithm>
#include <map>
#include <set>
#include <thread>

#include "about_dlg.hpp"
#include "aps/config.hpp"
#include "aps/dpapi.hpp"
#include "aps/engine_main.hpp"
#include "aps/log.hpp"
#include "aps/net.hpp"
#include "aps/path_util.hpp"
#include "aps/profile_io.hpp"
#include "aps/rule_matcher.hpp"
#include "aps/socks5_client.hpp"
#include "aps/string_util.hpp"
#include "app.hpp"
#include "i18n.hpp"
#include "pick_process_dlg.hpp"
#include "outlets_dlg.hpp"
#include "rule_edit_dlg.hpp"

namespace aps::gui {

namespace {

constexpr wchar_t kClassName[] = L"ApsMainWindow";
constexpr int IDC_BTN_START = 101, IDC_BTN_STOP = 102, IDC_LBL_STATE = 103,
              IDC_LBL_ADMIN = 104, IDC_EDIT_HOST = 105, IDC_EDIT_PORT = 106,
              IDC_EDIT_USER = 107, IDC_EDIT_PASS = 108, IDC_BTN_TEST = 109,
              IDC_LBL_TEST = 110, IDC_BTN_ADD = 111, IDC_BTN_PICK = 112,
              IDC_BTN_BROWSE = 113, IDC_BTN_FLUSH = 114, IDC_BTN_CLEARLOG = 115,
              IDC_BTN_ABOUT = 116, IDC_BTN_OUTLETS = 117,
              IDC_BTN_NODESWITCH = 118, IDC_CHK_AUTOSWITCH = 119,
              IDC_EDIT_APISECRET = 120,
              IDC_BTN_EXPORT = 121, IDC_BTN_IMPORT = 122,
              IDC_COMBO_REGION = 123, IDC_COMBO_CLASS = 124,
              IDC_CHK_COVERDIR = 125, IDC_BTN_SUBREFRESH = 126,
              IDC_CHK_DNSCLEAN = 127,
              IDC_BTN_OFFLINE = 128, IDC_LBL_EFFECTIVE = 129, IDC_BTN_SAVE_PROXY = 130,
              IDC_NODE_PANE = 131,
              IDC_BTN_SPEED_ROW = 2000,   // per-outlet speed buttons: 2000 + row
              IDC_LIST_RULES = 1001;

MainWindow* g_main = nullptr;

// Region preference options (code -> display). Codes are validated against
// the same whitelist in Config::validate.
struct RegionEntry {
    const wchar_t* label;
    const char* code;
};
constexpr RegionEntry kRegions[] = {
    {L"不限", ""},  {L"香港", "HK"}, {L"台湾", "TW"}, {L"新加坡", "SG"},
    {L"日本", "JP"}, {L"美国", "US"}, {L"韩国", "KR"}, {L"澳门", "MO"},
    {L"英国", "UK"}, {L"德国", "DE"},
};
constexpr size_t kRegionCount = sizeof(kRegions) / sizeof(kRegions[0]);

// Node-class preference options (code -> display). Same soft-preference
// semantics as the region dropdown; codes validated in Config::validate.
struct ClassEntry {
    const wchar_t* label;
    const char* code;
};
constexpr ClassEntry kClasses[] = {
    {L"不限", ""},    {L"IEPL", "IEPL"},       {L"家宽", "RES"},
    {L"原生", "NATIVE"}, {L"中转", "RELAY"},   {L"直连", "DIRECT"},
    {L"星链", "STARLINK"}, {L"进阶", "PREMIUM"},
};
constexpr size_t kClassCount = sizeof(kClasses) / sizeof(kClasses[0]);

// Multi-check popup menu: every checked item is part of the acceptable
// set (empty = 不限). Returns the new selection; unchanged on dismiss.
std::vector<std::string> showMultiCheckPopup(
    HWND owner, const RECT& anchor,
    const std::vector<std::pair<const char*, const wchar_t*>>& items,
    const std::vector<std::string>& selected) {
    std::vector<std::string> sel = selected;
    auto isSel = [&](const char* code) {
        for (const auto& s : sel) {
            if (s == code) return true;
        }
        return false;
    };
    HMENU menu = CreatePopupMenu();
    for (;;) {
        int n = GetMenuItemCount(menu);
        for (int i = n - 1; i >= 0; --i) RemoveMenu(menu, i, MF_BYPOSITION);
        for (size_t i = 0; i < items.size(); ++i) {
            // "不限" checks when nothing else is selected (it IS the empty
            // selection); a stray "" entry from an older build reads as
            // selected too, so this also self-heals it on the next pick.
            bool check = items[i].first[0] == '\0'
                             ? sel.empty() ||
                                   (sel.size() == 1 && sel[0].empty())
                             : isSel(items[i].first);
            AppendMenuW(menu,
                        MF_STRING | (check ? MF_CHECKED : 0),
                        static_cast<UINT_PTR>(i + 1), items[i].second);
        }
        int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                                 anchor.left, anchor.bottom, 0, owner, nullptr);
        if (cmd == 0) break;
        const char* code = items[static_cast<size_t>(cmd) - 1].first;
        if (*code == '\0') {
            // "不限": clear the whole selection. Pushing an empty-string
            // entry instead wrote ["SG",...,""] — a config the parser
            // REJECTS, which the next GUI start treated as corrupt and
            // answered by wiping the user's whole config (measured
            // 2026-08-31: rules gone, "config reloaded: rules=0").
            sel.clear();
            continue;
        }
        bool found = false;
        for (auto it = sel.begin(); it != sel.end(); ++it) {
            if (*it == code) {
                sel.erase(it);
                found = true;
                break;
            }
        }
        if (!found) sel.push_back(code);
    }
    DestroyMenu(menu);
    return sel;
}

std::wstring selectionSummary(
    const std::vector<std::string>& sel,
    const std::vector<std::pair<const char*, const wchar_t*>>& items) {
    if (sel.empty()) return L"不限";
    std::wstring out;
    for (const auto& code : sel) {
        for (const auto& it : items) {
            if (it.first == code) {
                if (!out.empty()) out += L"+";
                out += it.second;
                break;
            }
        }
    }
    return out;
}

LRESULT CALLBACK wndProcForward(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(wnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
    }
    auto* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(wnd, GWLP_USERDATA));
    if (self) return self->wndProc(wnd, msg, wp, lp);
    return DefWindowProcW(wnd, msg, wp, lp);
}

const wchar_t* stateLabel(const std::string& s) {
    if (s == "RUNNING") return txt::kStateRunning;
    if (s == "DEGRADED") return txt::kStateDegraded;
    if (s == "STARTING") return txt::kStateStarting;
    if (s == "DRAINING") return txt::kStateDraining;
    if (s == "STOPPING") return txt::kStateStopping;
    if (s == "STOPPED") return txt::kStateStopped;
    return txt::kStateUnknown;
}

// "prefix: utf8detail" as a wide string (for MessageBox).
std::wstring msgWith(const wchar_t* prefix, const std::string& utf8) {
    return std::wstring(prefix) + L": " + utf8ToWide(utf8);
}

}  // namespace

MainWindow* MainWindow::create(HINSTANCE inst) {
    WNDCLASSW wc{};
    // CS_HREDRAW | CS_VREDRAW: the client area is invalidated on every
    // resize step, so the layout repaints LIVE during a drag instead of
    // showing overlapping stale frames until the resize ends.
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndProcForward;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(101));
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClassName;
    ATOM atom = RegisterClassW(&wc);
    guiDiagStep(atom ? "win: class registered" : "win: REGISTER CLASS FAILED");

    auto* self = new MainWindow();
    self->inst_ = inst;
    self->taskbarCreatedMsg_ = RegisterWindowMessageW(L"TaskbarCreated");
    guiDiagStep(self->taskbarCreatedMsg_ != 0
                    ? "tray: TaskbarCreated registered"
                    : "tray: TASKBARCREATED REGISTRATION FAILED");
    self->cfg_ = loadOrCreateConfig();
    guiDiagStep("win: config loaded");

    RECT rc{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &rc, 0);
    // 830 keeps the window under a 1080p work area even at 125% scaling
    // (the "活动连接" section below the rules list shares the stretch).
    int w = std::min<int>(Scaled(1010), rc.right - rc.left);
    int h = std::min<int>(Scaled(900), rc.bottom - rc.top);
    self->hwnd_ = CreateWindowExW(0, kClassName, txt::kAppTitle,
                                  WS_OVERLAPPEDWINDOW | WS_VSCROLL | WS_HSCROLL |
                                      WS_CLIPCHILDREN,
                                  rc.left, rc.top, w, h,
                                  nullptr, nullptr, inst, self);
    guiDiagStep(self->hwnd_ ? "win: CreateWindowExW ok" : "win: CREATEWINDOW FAILED");
    g_main = self;
    ShowWindow(self->hwnd_, SW_SHOW);
    UpdateWindow(self->hwnd_);
    return self;
}

void MainWindow::buildUi() {
    auto Sc = [](int v) { return Scaled(v); };
    auto mkStatic = [&](const wchar_t* text, int x, int y, int w, int h) {
        return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, Sc(x), Sc(y),
                             Sc(w), Sc(h), hwnd_, nullptr, inst_, nullptr);
    };
    auto mkEdit = [&](int id, int x, int y, int w, int h, DWORD extra = 0) {
        return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL |
                                   extra,
                               Sc(x), Sc(y), Sc(w), Sc(h), hwnd_,
                               reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), inst_,
                               nullptr);
    };
    auto mkButton = [&](const wchar_t* text, int id, int x, int y, int w, int h) {
        return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                                  BS_PUSHBUTTON,
                             Sc(x), Sc(y), Sc(w), Sc(h), hwnd_,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), inst_,
                             nullptr);
    };

    // --- engine group -------------------------------------------------------
    mkStatic(txt::kEngineGroup, 12, 10, 160, 20);
    btnStart_ = mkButton(txt::kStartEngine, IDC_BTN_START, 170, 8, 110, 28);
    btnStop_ = mkButton(txt::kStopEngine, IDC_BTN_STOP, 290, 8, 110, 28);
    mkStatic(txt::kEngineState, 420, 13, 80, 20);
    lblState_ = CreateWindowW(L"STATIC", txt::kStateStopped, WS_CHILD | WS_VISIBLE,
                              Sc(505), Sc(13), Sc(210), Sc(20), hwnd_, nullptr, inst_,
                              nullptr);
    mkStatic(txt::kAdminState, 720, 13, 100, 20);
    lblAdmin_ = CreateWindowW(L"STATIC",
                              crypto::isProcessElevated() ? txt::kYes : txt::kNo,
                              WS_CHILD | WS_VISIBLE, Sc(825), Sc(13), Sc(40), Sc(20),
                              hwnd_, nullptr, inst_, nullptr);

    // --- proxy group --------------------------------------------------------
    mkStatic(L"手动代理配置（自动发现的内核使用其实际端口）", 12, 48, 650, 20);
    mkStatic(txt::kProxyHost, 12, 78, 80, 20);
    editHost_ = mkEdit(IDC_EDIT_HOST, 96, 76, 130, 22);
    mkStatic(txt::kProxyPort, 240, 78, 70, 20);
    editPort_ = mkEdit(IDC_EDIT_PORT, 312, 76, 70, 22, ES_NUMBER);
    mkStatic(txt::kProxyProtocol, 396, 78, 120, 20);
    CreateWindowW(L"STATIC", L"SOCKS5（兼容 Mixed 端口）", WS_CHILD | WS_VISIBLE,
                  Sc(520), Sc(78), Sc(230), Sc(20), hwnd_, nullptr, inst_, nullptr);
    mkStatic(txt::kProxyUser, 12, 108, 120, 20);
    editUser_ = mkEdit(IDC_EDIT_USER, 136, 106, 180, 22);
    mkStatic(txt::kProxyPass, 330, 108, 120, 20);
    editPass_ = mkEdit(IDC_EDIT_PASS, 454, 106, 180, 22, ES_PASSWORD);
    btnTest_ = mkButton(L"检测当前出口", IDC_BTN_TEST, 660, 104, 140, 26);
    mkButton(L"保存手动配置", IDC_BTN_SAVE_PROXY, 810, 104, 160, 26);
    lblTestResult_ = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, Sc(480),
                                   Sc(134), Sc(490), Sc(22), hwnd_,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LBL_TEST)), inst_,
                                   nullptr);
    mkStatic(txt::kApiSecret, 12, 134, 170, 20);
    editApiSecret_ = mkEdit(IDC_EDIT_APISECRET, 184, 132, 280, 22, ES_PASSWORD);
    lblEffectiveProxy_ = mkStatic(L"当前出口：等待引擎报告", 12, 162, 960, 26);
    SetWindowLongPtrW(lblEffectiveProxy_, GWLP_ID, IDC_LBL_EFFECTIVE);

    SetWindowTextW(editHost_, utf8ToWide(cfg_.cfg.proxy.host).c_str());
    SetWindowTextW(editPort_, std::to_wstring(cfg_.cfg.proxy.port).c_str());
    SetWindowTextW(editUser_, utf8ToWide(cfg_.cfg.proxy.username).c_str());

    // --- rules group ----------------------------------------------------------
    mkStatic(txt::kRulesGroup, 12, 194, 420, 20);
    chkCoverDir_ = CreateWindowW(
        L"BUTTON", txt::kCoverAppDirAlways,
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, Sc(438), Sc(191), Sc(215),
        Sc(22), hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CHK_COVERDIR)), inst_,
        nullptr);
    SendMessageW(chkCoverDir_, BM_SETCHECK,
                 cfg_.cfg.routing.coverAppDirAlways ? BST_CHECKED : BST_UNCHECKED,
                 0);
    btnAdd_ = mkButton(txt::kAddProgram, IDC_BTN_ADD, 660, 190, 100, 26);
    btnPick_ = mkButton(txt::kPickProcess, IDC_BTN_PICK, 770, 190, 110, 26);
    btnBrowse_ = mkButton(txt::kBrowseExe, IDC_BTN_BROWSE, 890, 190, 80, 26);

    RulesView::Callbacks rcb;
    rcb.onToggle = [this](const std::string& id, bool en) { toggleRule(id, en); };
    rcb.onEdit = [this](const std::string& id) { editRuleUi(id); };
    rcb.onDelete = [this](const std::string& id) { deleteRuleUi(id); };
    rules_.setCallbacks(std::move(rcb));
    rules_.create(hwnd_, inst_, Sc(12), Sc(190), Sc(960), Sc(350));
    refreshRules();

    // --- active connections section (fed by STATS.connections) ---------------
    lblConns_ = mkStatic(txt::kConnectionsGroup, 12, 556, 500, 20);
    conns_.create(hwnd_, inst_, Sc(12), Sc(580), Sc(960), Sc(120));

    btnFlush_ = mkButton(txt::kFlushConns, IDC_BTN_FLUSH, 12, 528, 180, 26);
    btnClearLog_ = mkButton(txt::kClearLog, IDC_BTN_CLEARLOG, 200, 528, 100, 26);
    btnAbout_ = mkButton(txt::kAbout, IDC_BTN_ABOUT, 308, 528, 80, 26);
    btnOutlets_ = mkButton(txt::kManageOutlets, IDC_BTN_OUTLETS, 396, 528, 100, 26);
    btnExport_ = mkButton(txt::kExportConfig, IDC_BTN_EXPORT, 700, 528, 96, 26);
    btnImport_ = mkButton(txt::kImportConfig, IDC_BTN_IMPORT, 804, 528, 96, 26);

    chkAutoSwitch_ = CreateWindowW(L"BUTTON", txt::kAutoSwitch,
                                   WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, Sc(662),
                                   Sc(531), Sc(110), Sc(22), hwnd_,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CHK_AUTOSWITCH)),
                                   inst_, nullptr);
    SendMessageW(chkAutoSwitch_, BM_SETCHECK,
                 cfg_.cfg.nodeMonitor.enabled ? BST_CHECKED : BST_UNCHECKED, 0);
    // Protection is process-scoped unless the advanced legacy option was
    // explicitly enabled. The master switch now applies live to both families.
    chkDnsClean_ = CreateWindowW(L"BUTTON", cfg_.cfg.routing.dnsCleanupGlobal ? L"全局 DNS" : txt::kDnsCleanSwitch,
                                 WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, Sc(614),
                                 Sc(531), Sc(88), Sc(22), hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CHK_DNSCLEAN)),
                                 inst_, nullptr);
    SendMessageW(chkDnsClean_, BM_SETCHECK,
                 cfg_.cfg.routing.dnsCleanup ? BST_CHECKED : BST_UNCHECKED, 0);
    lblNodeTitle_ = mkStatic(txt::kNodeStatus, 12, 560, 90, 20);
    lblRegion_ = mkStatic(txt::kRegionLabel, 108, 560, 55, 20);
    {
        std::vector<std::pair<const char*, const wchar_t*>> items;
        for (size_t i = 0; i < kRegionCount; ++i) {
            items.emplace_back(kRegions[i].code, kRegions[i].label);
        }
        std::wstring text = selectionSummary(cfg_.cfg.nodeMonitor.regions, items);
        btnRegion_ = mkButton(text.c_str(), IDC_COMBO_REGION, 162, 558, 150, 24);
    }
    lblClass_ = mkStatic(txt::kClassLabel, 324, 560, 55, 20);
    {
        std::vector<std::pair<const char*, const wchar_t*>> items;
        for (size_t i = 0; i < kClassCount; ++i) {
            items.emplace_back(kClasses[i].code, kClasses[i].label);
        }
        std::wstring text =
            selectionSummary(cfg_.cfg.nodeMonitor.nodeClasses, items);
        btnClass_ = mkButton(text.c_str(), IDC_COMBO_CLASS, 378, 558, 140, 24);
    }
    btnSubRefresh_ = mkButton(txt::kSubRefresh, IDC_BTN_SUBREFRESH, 528, 558,
                              100, 24);
    btnOffline_ = mkButton(L"展开未启动内核", IDC_BTN_OFFLINE, 12, 590, 240, 24);
    nodePane_ = CreateWindowExW(WS_EX_CONTROLPARENT, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN,
        Sc(12), Sc(590), Sc(960), Sc(180), hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_NODE_PANE)), inst_, nullptr);
    SetWindowSubclass(nodePane_, nodePaneProc, 0, reinterpret_cast<DWORD_PTR>(this));
    // Per-outlet status rows are created dynamically in refreshNodeStatus.
    lblNotice_ = CreateWindowW(L"STATIC", txt::kMvpNotice, WS_CHILD | WS_VISIBLE,
                               Sc(12), Sc(602), Sc(960), Sc(64), hwnd_, nullptr, inst_,
                               nullptr);

    EnumChildWindows(hwnd_, [](HWND h, LPARAM) -> BOOL {
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
        return TRUE;
    }, 0);

    fixedControls_.clear();
    for (HWND child = GetWindow(hwnd_, GW_CHILD); child;
         child = GetWindow(child, GW_HWNDNEXT)) {
        RECT rect{};
        GetWindowRect(child, &rect);
        MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&rect), 2);
        fixedControls_.push_back({child, rect});
    }

    tray_.create(hwnd_);
    // Node rows exist from the very first paint (local config driven), so
    // engine restarts can never blank the section again.
    ensureRowsFromConfig();
    applyEngineData(lastEngineOutlets_);
    updateRadioChecks();
    refreshClassButtonText();
    if (subRefreshActive_) SetWindowTextW(btnSubRefresh_, txt::kSubRefreshing);

    // IPC client wiring (background thread -> UI via posted messages).
    // Callbacks capture `this` (hwnd_ is already valid inside WM_CREATE);
    // the old code used the global mainHwnd(), which is still null while the
    // window is being created — connection notifications posted then were
    // silently dropped and the UI stayed "引擎未连接" forever.
    if (!engine_) {
        EngineClient::Callbacks cbs;
        cbs.onStatus = [this](const std::string& s) {
            auto* heap = new std::string(s);
            PostMessageW(hwnd_, WM_APP_PIPE_MSG, 0,
                         reinterpret_cast<LPARAM>(heap));
        };
        cbs.onStats = cbs.onStatus;
        cbs.onConnection = [this](bool connected) {
            PostMessageW(hwnd_, WM_APP_PIPE_STATE, connected ? 1 : 0, 0);
        };
        engine_ = std::make_unique<EngineClient>(std::move(cbs));
    }
    refreshStatusText();
    refreshEffectiveProxy(nullptr);
    RECT rc{}; GetClientRect(hwnd_, &rc);
    layout(rc.right, rc.bottom);
}

void MainWindow::layout(int w, int h) {
    if (!rules_.hwnd() || layingOut_ || w <= 0 || h <= 0) return;
    layingOut_ = true;
    const bool repaint = IsWindowVisible(hwnd_) != FALSE;
    if (repaint) SendMessageW(hwnd_, WM_SETREDRAW, FALSE, 0);
    // The node pane scrolls independently; long results and extra kernels
    // cannot compress either ListView or overlap the notice below it.
    const int viewW = w;
    w = std::max(w, Scaled(990));
    const int margin = Scaled(12);
    const int noticeH = Scaled(64);
    const int btnH = Scaled(26);
    const int titleH = Scaled(20);
    const int nodeW = w - 2 * margin;
    const int nodeClientW = nodeW - GetSystemMetricsForDpi(SM_CXVSCROLL, GetDpiForWindow(hwnd_));
    const int nodeContentH = layoutNodeRows(nodeClientW);
    const int nodeViewH = std::clamp(nodeContentH, Scaled(120), Scaled(260));
    const int minHeight = Scaled(220 + 140 + 32 + 140 + 8 + 34 + 28 + 4 + 8) +
                          nodeViewH + noticeH;
    const int contentH = std::max(h, minHeight);
    const int extra = contentH - minHeight;
    const int rulesH = Scaled(140) + extra / 2;
    const int connH = Scaled(140) + extra - extra / 2;
    const int connTitleY = Scaled(220) + rulesH + Scaled(8);
    const int connListY = connTitleY + titleH + Scaled(4);
    const int btnsY = connListY + connH + Scaled(8);
    const int titleY = btnsY + btnH + Scaled(8);
    const int firstRowY = titleY + Scaled(28);
    const int foldY = firstRowY + nodeViewH;
    const int noticeY = foldY + Scaled(4);
    scrollX_ = std::clamp(scrollX_, 0, w - viewW);
    scrollY_ = std::clamp(scrollY_, 0, contentH - h);
    SCROLLINFO si{sizeof(si), SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL};
    si.nMax = w - 1; si.nPage = viewW; si.nPos = scrollX_;
    SetScrollInfo(hwnd_, SB_HORZ, &si, TRUE);
    si.nMax = contentH - 1; si.nPage = h; si.nPos = scrollY_;
    SetScrollInfo(hwnd_, SB_VERT, &si, TRUE);
    for (const auto& c : fixedControls_) {
        MoveWindow(c.hwnd, c.rect.left, c.rect.top, c.rect.right - c.rect.left,
                   c.rect.bottom - c.rect.top, FALSE);
    }
    MoveWindow(rules_.hwnd(), margin, Scaled(220), w - 2 * margin, rulesH, TRUE);

    auto move = [](HWND c, int x, int y, int cw, int ch) {
        if (c) MoveWindow(c, x, y, cw, ch, TRUE);
    };
    move(lblConns_, margin, connTitleY, Scaled(500), titleH);
    MoveWindow(conns_.hwnd(), margin, connListY, w - 2 * margin, connH, TRUE);
    move(btnFlush_, margin, btnsY, Scaled(180), btnH);
    move(btnClearLog_, margin + Scaled(188), btnsY, Scaled(100), btnH);
    move(btnAbout_, margin + Scaled(296), btnsY, Scaled(80), btnH);
    move(btnOutlets_, margin + Scaled(384), btnsY, Scaled(100), btnH);
    move(chkAutoSwitch_, margin + Scaled(500), btnsY + Scaled(2), Scaled(110),
         Scaled(22));
    move(chkDnsClean_, margin + Scaled(614), btnsY + Scaled(2), Scaled(88),
         Scaled(22));
    move(btnExport_, margin + Scaled(700), btnsY, Scaled(96), btnH);
    move(btnImport_, margin + Scaled(804), btnsY, Scaled(96), btnH);
    move(lblNodeTitle_, margin, titleY, Scaled(90), titleH);
    move(lblRegion_, margin + Scaled(96), titleY, Scaled(55), titleH);
    move(btnRegion_, margin + Scaled(150), titleY - Scaled(2), Scaled(150),
         Scaled(24));
    move(lblClass_, margin + Scaled(312), titleY, Scaled(55), titleH);
    move(btnClass_, margin + Scaled(366), titleY - Scaled(2), Scaled(140),
         Scaled(24));
    move(btnSubRefresh_, margin + Scaled(516), titleY - Scaled(2), Scaled(100),
         Scaled(24));
    move(nodePane_, margin, firstRowY, nodeW, nodeViewH);
    nodeScrollY_ = std::clamp(nodeScrollY_, 0, std::max(0, nodeContentH - nodeViewH));
    SCROLLINFO nodeSi{sizeof(nodeSi), SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL};
    nodeSi.nMax = nodeContentH - 1; nodeSi.nPage = nodeViewH; nodeSi.nPos = nodeScrollY_;
    SetScrollInfo(nodePane_, SB_VERT, &nodeSi, TRUE);
    RECT nodeRc{}; GetClientRect(nodePane_, &nodeRc);
    layoutNodeRows(nodeRc.right);
    move(btnOffline_, margin + Scaled(636), titleY - Scaled(2), Scaled(300), Scaled(24));
    ShowWindow(btnOffline_, offlineCount_ ? SW_SHOW : SW_HIDE);
    move(lblNotice_, margin, noticeY, w - 2 * margin, noticeH);
    for (HWND child = GetWindow(hwnd_, GW_CHILD); child;
         child = GetWindow(child, GW_HWNDNEXT)) {
        RECT rect{};
        GetWindowRect(child, &rect);
        MapWindowPoints(nullptr, hwnd_, reinterpret_cast<POINT*>(&rect), 2);
        SetWindowPos(child, nullptr, rect.left - scrollX_, rect.top - scrollY_,
                     0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    layingOut_ = false;
    if (repaint) SendMessageW(hwnd_, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(hwnd_, nullptr, nullptr,
                 RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
}

void MainWindow::scrollPage(int bar, int code, int position) {
    SCROLLINFO si{sizeof(si), SIF_ALL};
    GetScrollInfo(hwnd_, bar, &si);
    int next = si.nPos;
    switch (code) {
        case SB_LINEUP: next -= Scaled(28); break;
        case SB_LINEDOWN: next += Scaled(28); break;
        case SB_PAGEUP: next -= static_cast<int>(si.nPage); break;
        case SB_PAGEDOWN: next += static_cast<int>(si.nPage); break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: next = si.nTrackPos; break;
        case SB_TOP: next = 0; break;
        case SB_BOTTOM: next = si.nMax; break;
        default: next += position; break;
    }
    next = std::clamp(next, 0, std::max(0, si.nMax - static_cast<int>(si.nPage) + 1));
    if (next == si.nPos) return;
    (bar == SB_VERT ? scrollY_ : scrollX_) = next;
    RECT rc{}; GetClientRect(hwnd_, &rc);
    layout(rc.right, rc.bottom);
}

LRESULT CALLBACK MainWindow::nodePaneProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp,
                                         UINT_PTR subclass, DWORD_PTR context) {
    auto* self = reinterpret_cast<MainWindow*>(context);
    switch (msg) {
        case WM_VSCROLL: self->scrollNodes(LOWORD(wp)); return 0;
        case WM_MOUSEWHEEL:
            self->scrollNodes(-1, -GET_WHEEL_DELTA_WPARAM(wp) * Scaled(60) / WHEEL_DELTA);
            return 0;
        case WM_COMMAND:
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN:
            return SendMessageW(self->hwnd_, msg, wp, lp);
        case WM_NCDESTROY:
            RemoveWindowSubclass(wnd, nodePaneProc, subclass);
            break;
    }
    return DefSubclassProc(wnd, msg, wp, lp);
}

void MainWindow::scrollNodes(int code, int position) {
    SCROLLINFO si{sizeof(si), SIF_ALL};
    GetScrollInfo(nodePane_, SB_VERT, &si);
    int next = si.nPos;
    switch (code) {
        case SB_LINEUP: next -= Scaled(28); break;
        case SB_LINEDOWN: next += Scaled(28); break;
        case SB_PAGEUP: next -= static_cast<int>(si.nPage); break;
        case SB_PAGEDOWN: next += static_cast<int>(si.nPage); break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: next = si.nTrackPos; break;
        case SB_TOP: next = 0; break;
        case SB_BOTTOM: next = si.nMax; break;
        default: next += position; break;
    }
    next = std::clamp(next, 0, std::max(0, si.nMax - static_cast<int>(si.nPage) + 1));
    if (next == si.nPos) return;
    nodeScrollY_ = next;
    SetScrollPos(nodePane_, SB_VERT, next, TRUE);
    RECT rc{}; GetClientRect(nodePane_, &rc);
    SendMessageW(nodePane_, WM_SETREDRAW, FALSE, 0);
    layoutNodeRows(rc.right);
    SendMessageW(nodePane_, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(nodePane_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void MainWindow::refreshRules() {
    std::vector<RulesView::RuleRow> rows;
    for (const auto& r : cfg_.cfg.rules) {
        RulesView::RuleRow row;
        row.ruleId = r.id;
        row.enabled = r.enabled;
        row.path = utf8ToWide(r.path);
        row.name = utf8ToWide(r.name);
        rows.push_back(std::move(row));
    }
    rules_.setRules(rows);
}

void MainWindow::refreshStatusText() {
    const wchar_t* s = stateLabel(engineState_);
    std::wstring text = pipeConnected_ ? s : (std::wstring(s) + L"（引擎未连接）");
    SetWindowTextW(lblState_, text.c_str());
    tray_.setTooltip((std::wstring(txt::kAppTitle) + L" - " + s).c_str());
    EnableWindow(btnStop_, pipeConnected_);
    EnableWindow(btnStart_, !pipeConnected_ && !engineLaunching_);
}

void MainWindow::applyProxySettingsFromUi() {
    wchar_t host[128] = L"", port[16] = L"", user[256] = L"", pass[256] = L"";
    GetWindowTextW(editHost_, host, 128);
    GetWindowTextW(editPort_, port, 16);
    GetWindowTextW(editUser_, user, 256);
    GetWindowTextW(editPass_, pass, 256);
    std::string hostUtf8 = wideToUtf8(host);
    int portNum = _wtoi(port);
    if (hostUtf8.empty()) hostUtf8 = "127.0.0.1";
    if (portNum < 1 || portNum > 65535) portNum = 7891;
    bool changed = cfg_.cfg.proxy.host != hostUtf8 || cfg_.cfg.proxy.port != portNum ||
                   cfg_.cfg.proxy.username != wideToUtf8(user);
    cfg_.cfg.proxy.host = hostUtf8;
    cfg_.cfg.proxy.port = portNum;
    cfg_.cfg.proxy.username = wideToUtf8(user);
    if (GetWindowTextLengthW(editPass_) > 0) {
        cfg_.cfg.setPlainPassword(wideToUtf8(pass));
        changed = true;
    }
    if (editApiSecret_ && GetWindowTextLengthW(editApiSecret_) > 0) {
        wchar_t apisecret[256] = L"";
        GetWindowTextW(editApiSecret_, apisecret, 256);
        cfg_.cfg.proxy.clashApi.secretEnc =
            crypto::protectToBase64(wideToUtf8(apisecret));
        cfg_.cfg.proxy.clashApi.host = "127.0.0.1";  // keep auto-detect on
        changed = true;
    }
    std::string err;
    if (changed && !saveConfig(cfg_, &err)) {
        MessageBoxW(hwnd_, msgWith(txt::kSaveFailed, err).c_str(),
                    txt::kAppTitle, MB_ICONERROR);
        return;
    }
    if (changed && engine_ && engine_->connected()) {
        engine_->sendReload();
    }
}

std::string MainWindow::proxyTargetKey() const {
    if (const auto* port = effectiveProxy_.find("port"); port && port->asInt() > 0) {
        const auto* host = effectiveProxy_.find("host");
        const auto* id = effectiveProxy_.find("id");
        return (id ? id->asString() : "") + "|" +
               (host ? host->asString() : "") + ":" + std::to_string(port->asInt());
    }
    if (pipeConnected_) return "";
    wchar_t host[128]{}, port[16]{};
    GetWindowTextW(editHost_, host, 128); GetWindowTextW(editPort_, port, 16);
    return "manual|" + wideToUtf8(host) + ":" + wideToUtf8(port);
}

void MainWindow::refreshEffectiveProxy(const json::Value* proxy) {
    if (proxy && proxy->isObject()) effectiveProxy_ = *proxy;
    const std::string key = proxyTargetKey();
    std::wstring text;
    if (const auto* port = effectiveProxy_.find("port"); port && port->asInt() > 0) {
        const auto* name = effectiveProxy_.find("name");
        text = L"新连接默认出口：" + utf8ToWide(name ? name->asString() : "") + L"  " +
               utf8ToWide(key.substr(key.find('|') + 1));
        if (const auto* fallback = effectiveProxy_.find("fallback"); fallback && fallback->asBool())
            text += L"（所选出口未就绪，使用默认端口）";
        text += L"；单独绑定出口的规则以活动连接为准";
        SetWindowTextW(btnTest_, L"检测当前出口");
    } else {
        text = pipeConnected_ ? L"当前出口：等待引擎报告实际地址" :
                                L"引擎未连接；检测按钮仅检查手动配置端口";
        SetWindowTextW(btnTest_, pipeConnected_ ? L"等待出口信息" : L"检测手动端口");
    }
    SetWindowTextW(lblEffectiveProxy_, text.c_str());
    if (key != proxyTestKey_) proxyTestDetail_.clear();
    SetWindowTextW(lblTestResult_, utf8ToWide(proxyTestDetail_).c_str());
    EnableWindow(btnTest_, !key.empty() && !proxyTestThread_.joinable());
}

void MainWindow::testProxyAsync() {
    if (proxyTestThread_.joinable()) return;
    // A read-only test must not save/reload an unrelated manual port while
    // the engine is actually routing through an auto-discovered outlet.
    std::string id = "__default__", host = cfg_.cfg.proxy.host;
    int port = cfg_.cfg.proxy.port;
    if (const auto* p = effectiveProxy_.find("port"); p && p->asInt() > 0) {
        port = static_cast<int>(p->asInt());
        if (const auto* v = effectiveProxy_.find("host")) host = v->asString();
        if (const auto* v = effectiveProxy_.find("id")) id = v->asString();
    } else {
        if (pipeConnected_) return;  // never substitute the stale manual field
        wchar_t address[128]{}, number[16]{};
        GetWindowTextW(editHost_, address, 128);
        GetWindowTextW(editPort_, number, 16);
        host = wideToUtf8(address); port = _wtoi(number);
    }
    auto ip = parseIpv4(host);
    if (!ip || port <= 0 || port > 65535) {
        SetWindowTextW(lblTestResult_, L"请填写有效的 IPv4 地址和端口");
        return;
    }
    std::string user, pass;
    if (id == "__default__") {
        user = cfg_.cfg.proxy.username; pass = cfg_.cfg.plainPassword();
    } else {
        for (const auto& outlet : cfg_.cfg.outlets) {
            if (outlet.id != id) continue;
            user = outlet.username;
            pass = crypto::unprotectFromBase64(outlet.passwordEnc, nullptr);
        }
    }
    if (!pipeConnected_ && !effectiveProxy_.find("port")) {
        wchar_t username[256]{}, password[256]{};
        GetWindowTextW(editUser_, username, 256); GetWindowTextW(editPass_, password, 256);
        user = wideToUtf8(username);
        if (*password) pass = wideToUtf8(password);
    }
    const std::string endpoint = host + ":" + std::to_string(port);
    proxyTestKey_ = proxyTargetKey();
    proxyTestDetail_ = endpoint + " SOCKS5 检测中…";
    SetWindowTextW(lblTestResult_, utf8ToWide(proxyTestDetail_).c_str());
    EnableWindow(btnTest_, FALSE);
    const HWND target = hwnd_;
    const auto generation = ++proxyTestGeneration_;
    proxyTestThread_ = std::thread([target, generation, ip = *ip, port, user, pass, endpoint]() {
        int latency = -1;
        std::string err;
        bool ok = Socks5Client::probe(net::Endpoint4{ip, static_cast<uint16_t>(port)},
                                     3000, &latency, &err, user, pass);
        std::string detail = endpoint + (ok ? " SOCKS5 握手正常（" + std::to_string(latency) + "ms）；目标服务未验证"
                                            : " SOCKS5 检测失败：" + err);
        auto* result = new std::string(ok ? "OK|" : "FAIL|");
        *result += detail;
        if (!PostMessageW(target, WM_APP_PROXY_TEST, generation, reinterpret_cast<LPARAM>(result)))
            delete result;
    });
}

void MainWindow::onProxyTestResult(bool ok, const std::string& detail) {
    (void)ok;
    if (proxyTestKey_ != proxyTargetKey()) return;
    proxyTestDetail_ = detail;
    SetWindowTextW(lblTestResult_, utf8ToWide(detail).c_str());
}

void MainWindow::addRuleFromPath(const std::wstring& path, const wchar_t* name,
                                 const Rule* fromDialog) {
    // New rules are stored in the version-robust wildcard form: version-
    // bearing directory segments become '*' so auto-updating apps (Store
    // apps, app-1.2.3 dirs, ...) never silently fall out of the rule.
    const std::wstring norm = versionRobustPath(path);
    // Loop protection: refuse to add the proxy core or ourselves.
    std::wstring selfPath = currentModulePath();
    if (RuleMatcher::isExcludedPath(cfg_.cfg, selfPath, path)) {
        MessageBoxW(hwnd_, txt::kExcludedPath, txt::kAppTitle, MB_ICONWARNING);
        return;
    }
    Rule r;
    r.id = newId();
    r.path = wideToUtf8(norm);
    r.name = name ? wideToUtf8(name) : wideToUtf8(baseName(path));
    r.enabled = true;
    r.includeChildren = true;   // whole-app coverage by default
    // Choices made in the add-rule dialog (outlet / action) must survive;
    // the old call consumed only the exe path and dropped everything else.
    if (fromDialog) {
        if (!fromDialog->name.empty()) r.name = fromDialog->name;
        r.outlet = fromDialog->outlet;
        r.action = fromDialog->action;
        r.includeChildren = fromDialog->includeChildren;
    }
    // Guard against system-wide directories (a rule there would proxy
    // every system tool — almost certainly not intended).
    std::wstring dirKey = canonicalPathKey(dirName(path));
    if (dirKey.rfind(L"c:\\windows", 0) == 0) {
        if (MessageBoxW(hwnd_, txt::kWarnSystemDir, txt::kAppTitle,
                        MB_YESNO | MB_ICONWARNING) != IDYES) {
            return;
        }
    }
    std::string err;
    if (!upsertRule(cfg_, r, &err)) {
        MessageBoxW(hwnd_, msgWith(txt::kSaveFailed, err).c_str(),
                    txt::kAppTitle, MB_ICONERROR);
        return;
    }
    refreshRules();
    if (engine_ && engine_->connected()) engine_->sendReload();
}

void MainWindow::editRuleUi(const std::string& ruleId) {
    auto r = findRule(cfg_, ruleId);
    if (!r) return;
    // Pass outlets so a non-default outlet binding is shown in the combo
    // (the old call passed nullptr and silently reset the display to 默认出口).
    auto edited = showRuleEditDialog(hwnd_, &*r, &cfg_.cfg.outlets);
    if (!edited) return;
    if (RuleMatcher::isExcludedPath(cfg_.cfg, currentModulePath(),
                                    utf8ToWide(edited->path))) {
        MessageBoxW(hwnd_, txt::kExcludedPath, txt::kAppTitle, MB_ICONWARNING);
        return;
    }
    std::string err;
    if (!upsertRule(cfg_, *edited, &err)) {
        MessageBoxW(hwnd_, msgWith(txt::kSaveFailed, err).c_str(),
                    txt::kAppTitle, MB_ICONERROR);
        return;
    }
    refreshRules();
    if (engine_ && engine_->connected()) engine_->sendReload();
}

void MainWindow::deleteRuleUi(const std::string& ruleId) {
    if (MessageBoxW(hwnd_, txt::kConfirmDelete, txt::kAppTitle,
                    MB_YESNO | MB_ICONQUESTION) != IDYES) {
        return;
    }
    std::string err;
    if (!deleteRule(cfg_, ruleId, &err)) {
        MessageBoxW(hwnd_, msgWith(txt::kDeleteFailed, err).c_str(),
                    txt::kAppTitle, MB_ICONERROR);
        return;
    }
    refreshRules();
    if (engine_ && engine_->connected()) engine_->sendReload();
}

void MainWindow::toggleRule(const std::string& ruleId, bool enabled) {
    for (auto& r : cfg_.cfg.rules) {
        if (r.id == ruleId) {
            r.enabled = enabled;
            std::string err;
            saveConfig(cfg_, &err);
            break;
        }
    }
    if (engine_ && engine_->connected()) engine_->sendReload();
}

void MainWindow::startEngineFromUi() {
    if (engineLaunching_) return;
    applyProxySettingsFromUi();
    engineLaunching_ = true;
    engineState_ = "STARTING";
    refreshStatusText();
    SetWindowTextW(lblState_, txt::kStateStarting);
    std::thread([this]() {
        bool ok = engine_->ensureEngineRunning();
        if (!ok) {
            PostMessageW(mainHwnd(), WM_APP_PIPE_STATE, 0, 0);
            auto* err = new std::string("LAUNCH_FAIL");
            PostMessageW(mainHwnd(), WM_APP_PIPE_MSG, 0, reinterpret_cast<LPARAM>(err));
        }
        engineLaunching_ = false;
    }).detach();
}

void MainWindow::stopEngineFromUi(bool confirm) {
    if (confirm && cfg_.cfg.ui.confirmStop) {
        if (MessageBoxW(hwnd_, txt::kConfirmStopEngine, txt::kAppTitle,
                        MB_YESNO | MB_ICONQUESTION) != IDYES) {
            return;
        }
    }
    if (engine_ && engine_->connected()) {
        engine_->sendStop();
    }
    engineState_ = "STOPPING";
    refreshStatusText();
}

void MainWindow::clearLogs() {
    std::wstring dir = appDataDir();
    if (dir.empty()) return;
    log::shutdown();
    log::clear();
    log::init(dir + L"\\logs", log::Level::Info, cfg_.cfg.logging.maxFileMb,
              cfg_.cfg.logging.maxFiles);
}

void MainWindow::exportConfigUi() {
    wchar_t file[MAX_PATH] = L"AppProxySwitch-配置.json";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"JSON 配置文件 (*.json)\0*.json\0所有文件 (*.*)\0*.*\0";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return;
    std::string err;
    if (!saveProfileFile(file, cfg_.cfg, &err)) {
        MessageBoxW(hwnd_, msgWith(txt::kExportFailed, err).c_str(), txt::kAppTitle,
                    MB_ICONERROR);
        return;
    }
    MessageBoxW(hwnd_, (std::wstring(txt::kExportOk) + L"：\n" + file).c_str(),
                txt::kAppTitle, MB_ICONINFORMATION);
}

void MainWindow::importConfigUi() {
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"JSON 配置文件 (*.json)\0*.json\0所有文件 (*.*)\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return;
    if (MessageBoxW(hwnd_, txt::kConfirmImport, txt::kAppTitle,
                    MB_YESNO | MB_ICONQUESTION) != IDYES) {
        return;
    }
    std::string text, err;
    std::vector<std::string> warns;
    if (!loadProfileFile(file, text, &err)) {
        MessageBoxW(hwnd_, msgWith(txt::kImportFailed, err).c_str(), txt::kAppTitle,
                    MB_ICONERROR);
        return;
    }
    Config out;
    if (!importProfileJson(text, cfg_.cfg, out, &err, &warns)) {
        MessageBoxW(hwnd_, msgWith(txt::kImportFailed, err).c_str(), txt::kAppTitle,
                    MB_ICONERROR);
        return;   // zero changes on failure
    }
    for (const auto& w : warns) log::wf("import: {}", w);
    cfg_.cfg = std::move(out);
    std::string serr;
    saveConfig(cfg_, &serr);          // atomic write; the engine's 1s config
                                      // watcher picks it up even without RELOAD
    if (engine_ && engine_->connected()) engine_->sendReload();
    refreshRules();
    ensureRowsFromConfig();
    updateRadioChecks();
    MessageBoxW(hwnd_, txt::kImportOk, txt::kAppTitle, MB_ICONINFORMATION);
}

void MainWindow::exitApp() {
    stopEngineFromUi(/*confirm=*/false);
    // Give the engine a moment to shut down cleanly.
    for (int i = 0; i < 30 && pipeConnected_; ++i) Sleep(50);
    DestroyWindow(hwnd_);
}

void MainWindow::onTrayEvent(LPARAM lParam) {
    if (lParam == WM_LBUTTONDBLCLK) {
        ShowWindow(hwnd_, SW_RESTORE);
        SetForegroundWindow(hwnd_);
        updateStatsVisibility();
        return;
    }
    if (lParam == WM_CONTEXTMENU || lParam == WM_RBUTTONUP) {
        switch (tray_.showMenu()) {
            case 5001:  // open
                ShowWindow(hwnd_, SW_RESTORE);
                SetForegroundWindow(hwnd_);
                updateStatsVisibility();
                break;
            case 5002: {  // enable all rules
                for (auto& r : cfg_.cfg.rules) r.enabled = true;
                std::string err;
                saveConfig(cfg_, &err);
                refreshRules();
                if (engine_ && engine_->connected()) engine_->sendReload();
                break;
            }
            case 5003:
                stopEngineFromUi(true);
                break;
            case 5004:
                exitApp();
                break;
            default:
                break;
        }
    }
}

void MainWindow::onPipeState(bool connected) {
    pipeConnected_ = connected;
    if (!connected) {
        engineState_ = "STOPPED";
        pendingOutlet_.clear();
        pendingOutletStarted_ = false;
        pendingTestRequestId_.clear();
        // Engine gone: every row's data is stale — show "检测中…" until the
        // next engine run pushes fresh results.
        for (auto& row : nodeRows_) {
            SetWindowTextW(row.lblStatus, L"引擎未连接，状态未知");
            SetWindowTextW(row.lblSwitch, L"");
            SetWindowTextW(row.lblMetadata, L"");
        }
        updateRadioChecks();
        conns_.setConnections({});   // no stale flow rows after engine death
        lastConnsJson_.clear();
        effectiveProxy_ = json::Value::makeObject();
        proxyTestKey_.clear();
        lastEngineOutlets_ = json::Value::makeArray();
    } else {
        // (Re)sync the STATS gate with the window's actual state — the
        // engine defaults to visible=true.
        updateStatsVisibility();
    }
    refreshStatusText();
    refreshEffectiveProxy(nullptr);
}

void MainWindow::updateStatsVisibility() {
    // "Visible" = shown AND not minimized: only then does the engine run the
    // per-second STATS push. A tray-hidden (or minimized) window has no
    // consumer for connection snapshots — building them would be pure waste.
    bool vis = IsWindowVisible(hwnd_) && !IsIconic(hwnd_);
    if (vis == statsVisSent_) return;
    statsVisSent_ = vis;
    if (engine_ && engine_->connected()) engine_->sendSetVisible(vis);
}

void MainWindow::onPipeMessage(const std::string& jsonLine) {
    if (jsonLine == "LAUNCH_FAIL") {
        MessageBoxW(hwnd_, txt::kEngineStartFail, txt::kAppTitle, MB_ICONERROR);
        engineState_ = "STOPPED";
        refreshStatusText();
        return;
    }
    json::Value v;
    std::string err;
    if (!json::Value::parse(jsonLine, v, &err)) return;
    const json::Value* t = v.find("type");
    if (!t || !t->isString()) return;
    const std::string type = t->asString();
    if (const auto* proxy = v.find("effective_proxy")) refreshEffectiveProxy(proxy);
    if (type == "STATUS") {
        const json::Value* s = v.find("state");
        if (s && s->isString()) engineState_ = s->asString();
        refreshStatusText();
        // Subscription-refresh round-trip: the engine's sub_refresh field is
        // the single source of truth for the button state. "running" ->
        // button shows 刷新中; any other value ends the cycle (button back
        // to normal + one popup). The active-flag gate fires the popup once
        // per engine cycle — repeated identical results still get feedback.
        const json::Value* sr = v.find("sub_refresh");
        if (sr && sr->isString() && !sr->asString().empty()) {
            const std::string m = sr->asString();
            if (m == "running") {
                subRefreshActive_ = true;
                SetWindowTextW(btnSubRefresh_, txt::kSubRefreshing);
            } else if (subRefreshActive_) {
                subRefreshActive_ = false;
                SetWindowTextW(btnSubRefresh_, txt::kSubRefresh);
                if (m.rfind("ok", 0) == 0) {
                    // "ok" or "ok（CFW: ...）" — partial failures surface as a
                    // NOTE inside the success box.
                    MessageBoxW(hwnd_, utf8ToWide(m).c_str(), txt::kAppTitle,
                                MB_ICONINFORMATION);
                } else if (m.starts_with("warning:")) {
                    MessageBoxW(hwnd_, utf8ToWide(m.substr(8)).c_str(), txt::kAppTitle,
                                MB_ICONWARNING);
                } else {
                    MessageBoxW(hwnd_, msgWith(txt::kSubRefreshFailed, m).c_str(),
                                txt::kAppTitle, MB_ICONERROR);
                }
            }
        }
    } else if (type == "STATS") {
        const json::Value* rules = v.find("rules");
        if (rules && rules->isArray()) {
            for (size_t i = 0; i < rules->size(); ++i) {
                const json::Value& r = rules->at(i);
                const json::Value* id = r.find("id");
                if (!id) continue;
                rules_.updateLiveData(
                    id->asString(),
                    static_cast<uint32_t>(r.find("last_pid") ? r.find("last_pid")->asInt() : 0),
                    r.find("conns") ? static_cast<uint64_t>(r.find("conns")->asInt()) : 0,
                    r.find("blocked") ? static_cast<uint64_t>(r.find("blocked")->asInt()) : 0,
                    r.find("bytes_up") ? static_cast<uint64_t>(r.find("bytes_up")->asInt()) : 0,
                    r.find("bytes_down") ? static_cast<uint64_t>(r.find("bytes_down")->asInt()) : 0,
                    r.find("last_error") ? utf8ToWide(r.find("last_error")->asString()) : std::wstring());
            }
        }
        const json::Value* conns = v.find("connections");
        if (conns && conns->isArray()) {
            // Power saving: while the window is hidden in the tray, the
            // per-second full ListView rebuild is pure waste — skip it; the
            // first tick after the window returns repopulates (<= 1s).
            if (!IsWindowVisible(hwnd_)) {
                lastConnsJson_.clear();  // force a rebuild on the next visible tick
            } else if (conns->dump() == lastConnsJson_) {
                // Identical payload: skip the expensive repopulation.
            } else {
                lastConnsJson_ = conns->dump();
            // id -> display name maps (rebuilt per second; lists are small).
            std::map<std::string, std::wstring> ruleNames, outletNames;
            for (const auto& r : cfg_.cfg.rules) {
                ruleNames[r.id] = utf8ToWide(r.name.empty() ? r.id : r.name);
            }
            for (const auto& o : cfg_.cfg.outlets) {
                outletNames[o.id] = utf8ToWide(o.name.empty() ? o.id : o.name);
            }
            std::vector<ConnectionsView::ConnRow> rows;
            for (size_t i = 0; i < conns->size(); ++i) {
                const json::Value& c = conns->at(i);
                auto strOf = [&](const char* k) {
                    const json::Value* f = c.find(k);
                    return f ? utf8ToWide(f->asString()) : std::wstring();
                };
                auto intOf = [&](const char* k, int64_t dflt) {
                    const json::Value* f = c.find(k);
                    return f ? f->asInt() : dflt;
                };
                ConnectionsView::ConnRow row;
                row.proc = strOf("proc");
                row.target = strOf("dst_ip") + L":" + std::to_wstring(intOf("dst_port", 0));
                const std::string ruleId = [&] {
                    const json::Value* f = c.find("rule_id");
                    return f ? f->asString() : std::string();
                }();
                auto rn = ruleNames.find(ruleId);
                row.ruleName = rn != ruleNames.end() ? rn->second : utf8ToWide(ruleId);
                const std::string outletId = [&] {
                    const json::Value* f = c.find("outlet_id");
                    return f ? f->asString() : std::string();
                }();
                if (outletId.empty() || outletId == "__default__") {
                    row.outletName = L"默认出口";
                } else {
                    auto on = outletNames.find(outletId);
                    if (on != outletNames.end()) row.outletName = on->second;
                    else {
                        // Discovered kernel id ("auto-<proc>"): show the
                        // kernel's display name when known, else the id.
                        std::wstring name = utf8ToWide(outletId);
                        for (const auto& k : kernels_) {
                            if (k.id == name) { name = k.name; break; }
                        }
                        row.outletName = name;
                    }
                }
                const std::string st = [&] {
                    const json::Value* f = c.find("state");
                    return f ? f->asString() : std::string("established");
                }();
                row.state = st == "syn" ? txt::kConnStateSyn
                            : st == "closing" ? txt::kConnStateClosing
                                              : txt::kConnStateEstab;
                row.bytesUp = static_cast<uint64_t>(intOf("bytes_up", 0));
                row.bytesDown = static_cast<uint64_t>(intOf("bytes_down", 0));
                row.durationMs = intOf("duration_ms", 0);
                row.key = strOf("app_ip") + L":" + std::to_wstring(intOf("app_port", 0)) +
                          L"/" + std::to_wstring(intOf("pid", 0)) + L"/" + row.target;
                row.host = strOf("host");
                rows.push_back(std::move(row));
            }
            conns_.setConnections(std::move(rows));
            }
        }
    } else if (type == "BYE") {
        engineState_ = "STOPPED";
        refreshStatusText();
    }
    const json::Value* outlets = v.find("outlets");
    if (outlets && outlets->isArray()) {
        refreshNodeStatus(*outlets, v.find("kernels"));
    }
}

void MainWindow::refreshNodeStatus(const json::Value& engineOutlets,
                                   const json::Value* kernels) {
    lastEngineOutlets_ = engineOutlets;
    // Kernel rows come from the ENGINE's discovery pushes (id/name/alive);
    // the default outlet and manual outlet rows come from LOCAL config. All
    // rows survive engine restarts; engine data only fills in status text.
    if (kernels && kernels->isArray()) {
        std::vector<KernelRow> fresh;
        for (size_t i = 0; i < kernels->size(); ++i) {
            const json::Value& k = kernels->at(i);
            if (!k.isObject()) continue;
            KernelRow row;
            row.id = utf8ToWide(k.find("id") ? k.find("id")->asString()
                                             : std::string());
            row.name = utf8ToWide(k.find("name") ? k.find("name")->asString()
                                                 : std::string());
            row.procName = row.name;
            row.alive = !(k.find("alive") && !k.find("alive")->asBool());
            if (const auto* port = k.find("socks_port"); row.alive && port && port->asInt() > 0)
                row.name += L":" + std::to_wstring(port->asInt());
            row.hasApi = k.find("api_port") && k.find("api_port")->asInt() != 0;
            if (auto has = k.find("has_api")) row.hasApi = has->asBool();
            if (auto error = k.find("discovery_error")) row.discoveryError = utf8ToWide(error->asString());
            row.seen = !k.find("seen") || k.find("seen")->asBool();
            if (row.id.empty()) continue;
            fresh.push_back(std::move(row));
        }
        kernels_ = std::move(fresh);
    }
    ensureRowsFromConfig();
    applyEngineData(engineOutlets);
    updateRadioChecks();
    RECT rc{}; GetClientRect(hwnd_, &rc);
    layout(rc.right, rc.bottom); // text changes can add/remove wrapped lines
}

void MainWindow::ensureRowsFromConfig() {
    // Desired row set = default outlet + configured outlets + discovered
    // kernels (engine-pushed, kept from the last STATUS/STATS).
    std::vector<std::pair<std::wstring, std::wstring>> want;
    want.emplace_back(L"__default__",
                      utf8ToWide(cfg_.cfg.proxy.host + ":" +
                                 std::to_string(cfg_.cfg.proxy.port)));
    for (const auto& o : cfg_.cfg.outlets) {
        want.emplace_back(utf8ToWide(o.id), utf8ToWide(o.name));
    }
    const size_t previousOfflineCount = offlineCount_;
    offlineCount_ = 0;
    auto required = [this](const KernelRow& k) {
        if (isOutletActive(k.id)) return true;
        return std::any_of(cfg_.cfg.rules.begin(), cfg_.cfg.rules.end(), [&](const auto& rule) {
            return rule.outlet == wideToUtf8(k.id);
        });
    };
    auto nameKey = [](const KernelRow& k) {
        return toLowerAscii(wideToUtf8(k.procName.empty() ? k.id : k.procName));
    };
    std::set<std::string> visibleNames;
    for (const auto& k : kernels_) {
        if (k.alive || required(k)) visibleNames.insert(nameKey(k));
    }
    std::vector<const KernelRow*> offlineRows;
    std::set<std::string> rememberedNames;
    for (const auto& k : kernels_) {
        if (k.alive || required(k)) {
            want.emplace_back(k.id, k.name.empty() ? k.id : k.name);
            continue;
        }
        // Historical instances contribute one name, and none when that
        // kernel is already represented by a live/explicitly bound outlet.
        const auto key = nameKey(k);
        if (visibleNames.count(key) || !rememberedNames.insert(key).second) continue;
        if (!k.seen) want.emplace_back(k.id, k.name.empty() ? k.id : k.name);
        else offlineRows.push_back(&k);
    }
    offlineCount_ = offlineRows.size();
    if (showOffline_) {
        for (const auto* k : offlineRows)
            want.emplace_back(k->id, k->name.empty() ? k->id : k->name);
    }
    SetWindowTextW(btnOffline_, ((showOffline_ ? std::wstring(L"收起未启动内核（")
                                              : std::wstring(L"展开未启动内核（")) +
                                std::to_wstring(offlineCount_) + L"）").c_str());
    // Matching outlet IDs alone do not prove the child controls still exist
    // (e.g. after a DPI rebuild or a failed CreateWindow). Repair stale rows.
    bool changed = want.size() != nodeRows_.size();
    if (!changed) {
        for (size_t i = 0; i < want.size(); ++i) {
            const auto& row = nodeRows_[i];
            auto valid = [this](HWND control) {
                return IsWindow(control) && GetParent(control) == nodePane_;
            };
            if (row.outletId != want[i].first || !valid(row.lblName) ||
                !valid(row.lblStatus) || !valid(row.lblMetadata) || !valid(row.lblSwitch) ||
                !valid(row.btnSpeed)) {
                changed = true;
                break;
            }
        }
    }
    if (!changed) {
        for (size_t i = 0; i < want.size(); ++i) {
            if (want[i].first.starts_with(L"auto-"))
                SetWindowTextW(nodeRows_[i].lblName, want[i].second.c_str());
        }
        if (previousOfflineCount != offlineCount_) {
            RECT rc{}; GetClientRect(hwnd_, &rc); layout(rc.right, rc.bottom);
        }
        return;
    }
    for (auto& r : nodeRows_) {
        if (r.lblName) DestroyWindow(r.lblName);
        if (r.lblStatus) DestroyWindow(r.lblStatus);
        if (r.lblMetadata) DestroyWindow(r.lblMetadata);
        if (r.lblSwitch) DestroyWindow(r.lblSwitch);
        if (r.btnSpeed) DestroyWindow(r.btnSpeed);
    }
    nodeRows_.clear();
    for (size_t i = 0; i < want.size(); ++i) {
        NodeRow row;
        row.outletId = want[i].first;
        row.lblName = CreateWindowW(
            L"STATIC", want[i].second.c_str(), WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 0, 0, 0, 0,
            nodePane_, nullptr, inst_, nullptr);
        row.lblStatus =
            CreateWindowW(L"STATIC", pipeConnected_ ? L"等待节点状态" : L"引擎未连接，状态未知",
                          WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 0, 0, 0, 0,
                          nodePane_, nullptr, inst_, nullptr);
        row.lblMetadata = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
                          0, 0, 0, 0, nodePane_, nullptr, inst_, nullptr);
        // Last line: test/switch result — keeps the first line short so it
        // never clips against the button at narrow widths.
        row.lblSwitch =
            CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 0, 0, 0, 0,
                          nodePane_, nullptr, inst_, nullptr);
        // Radio semantics (manually managed group): the ACTIVE outlet's
        // button stays pressed (checked); clicking another one tests AND
        // activates it.
        row.btnSpeed = CreateWindowW(
            L"BUTTON", L"测试并连接", WS_CHILD | WS_VISIBLE | BS_RADIOBUTTON,
            0, 0, 0, 0, nodePane_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_SPEED_ROW + i)),
            inst_, nullptr);
        SendMessageW(row.lblName, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()),
                     TRUE);
        SendMessageW(row.lblStatus, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()),
                     TRUE);
        SendMessageW(row.lblSwitch, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()),
                     TRUE);
        SendMessageW(row.lblMetadata, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
        SendMessageW(row.btnSpeed, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()),
                     TRUE);
        nodeRows_.push_back(std::move(row));
    }
    RECT rcAll{};
    GetClientRect(hwnd_, &rcAll);
    layout(rcAll.right, rcAll.bottom);
}

void MainWindow::applyEngineData(const json::Value& engineOutlets) {
    // Clear placeholders that belong to a previous connection state. Some
    // outlets (e.g. disabled manual entries) legitimately have no API row.
    for (const auto& row : nodeRows_) {
        bool present = false;
        for (size_t i = 0; i < engineOutlets.size(); ++i) {
            const auto* id = engineOutlets.at(i).find("id");
            if (id && utf8ToWide(id->asString()) == row.outletId) { present = true; break; }
        }
        if (present) continue;
        const wchar_t* label = pipeConnected_ ? L"等待节点状态" : L"引擎未连接，状态未知";
        for (const auto& outlet : cfg_.cfg.outlets) {
            if (utf8ToWide(outlet.id) != row.outletId) continue;
            if (!outlet.enabled) label = L"手动出口未启用";
            else if (!outlet.hasClashApi()) label = L"手动出口未配置节点控制器";
        }
        SetWindowTextW(row.lblStatus, label);
        SetWindowTextW(row.lblSwitch, L"");
        SetWindowTextW(row.lblMetadata, L"");
    }
    // Collect the provider's group names (for the class popup's 分组 entries).
    std::vector<std::wstring> groups;
    for (size_t i = 0; i < engineOutlets.size(); ++i) {
        const json::Value& o = engineOutlets.at(i);
        if (!o.isObject()) continue;
        const json::Value* g = o.find("groups");
        if (!g || !g->isArray()) continue;
        for (size_t k = 0; k < g->size(); ++k) {
            if (!g->at(k).isString()) continue;
            std::wstring name = utf8ToWide(g->at(k).asString());
            bool have = false;
            for (const auto& e : groups) {
                if (e == name) { have = true; break; }
            }
            if (!have) groups.push_back(name);
        }
    }
    if (groups != knownGroups_) {
        knownGroups_ = std::move(groups);
        refreshClassButtonText();  // the popup/label now offer the groups
    }
    for (size_t i = 0; i < engineOutlets.size(); ++i) {
        const json::Value& o = engineOutlets.at(i);
        if (!o.isObject()) continue;
        std::wstring id = utf8ToWide(o.find("id") ? o.find("id")->asString()
                                                  : std::string());
        std::wstring name = utf8ToWide(o.find("name") ? o.find("name")->asString()
                                                      : std::string());
        for (auto& row : nodeRows_) {
            if (row.outletId != id) continue;
            // The engine's name is authoritative: the default row shows the
            // AUTO-FOLLOWED port with a （自动） marker when the configured
            // port died (the local-config name would keep showing the stale
            // number).
            if (!name.empty() && !id.starts_with(L"auto-"))
                SetWindowTextW(row.lblName, name.c_str());
            bool api = o.find("api") && o.find("api")->asBool();
            bool alive = o.find("alive") && o.find("alive")->asBool();
            bool switching = o.find("switching") && o.find("switching")->asBool();
            int64_t lat = o.find("latency_ms") ? o.find("latency_ms")->asInt() : -1;
            std::string node = o.find("node") ? o.find("node")->asString()
                                              : std::string();
            std::string apiMsg = o.find("api_msg") ? o.find("api_msg")->asString()
                                                   : std::string();
            std::string detail = o.find("last_switch_detail")
                                     ? o.find("last_switch_detail")->asString()
                                     : std::string();
            std::wstring text;
            if (switching) {
                // A re-selection is measuring: keep showing "切换中…" — the
                // stale previous node must NOT repaint over it (that read as
                // "nothing happened" during slow region switches).
                text = txt::kRegionSwitching;
            } else if (!api) {
                text = apiMsg.empty() ? std::wstring(L"API 不可用")
                                      : utf8ToWide(apiMsg);
            } else if (alive) {
                text = utf8ToWide(node) + L"  " + (lat < 0 ? std::wstring(L"延迟待测") : std::to_wstring(lat) + L"ms");
            } else {
                text = utf8ToWide(node) + L" 不可达";
            }
            SetWindowTextW(row.lblStatus, text.c_str());
            std::wstring metadata;
            const auto* mode = o.find("runtime_mode");
            const std::string runtimeMode = mode ? mode->asString() : std::string();
            if (api && !node.empty()) {
                const auto region = o.find("region") ? o.find("region")->asString() : std::string();
                std::wstring regionLabel = region.empty() ? L"未知" : utf8ToWide(region);
                for (const auto& r : kRegions) if (!region.empty() && region == r.code) regionLabel = r.label;
                metadata = L"地区: " + regionLabel + L" · 类型: ";
                std::wstring labels;
                if (const auto* classes = o.find("node_classes"); classes && classes->isArray()) {
                    for (size_t c = 0; c < classes->size(); ++c) {
                        const auto code = classes->at(c).asString();
                        for (const auto& entry : kClasses) {
                            if (code != entry.code || code.empty()) continue;
                            if (!labels.empty()) labels += L"/";
                            labels += entry.label;
                        }
                    }
                }
                metadata += labels.empty() ? L"未知" : labels;
                if (const auto* group = o.find("group"); group && !group->asString().empty())
                    metadata += L" · 策略组: " + utf8ToWide(group->asString());
            }
            if (!runtimeMode.empty()) {
                if (!metadata.empty()) metadata += L" · ";
                metadata += L"模式: " + utf8ToWide(runtimeMode);
            }
            SetWindowTextW(row.lblMetadata, metadata.c_str());
            // "上次切换" on its OWN line: the first line stays short and
            // never clips against the button at narrow widths.
            const auto* warning = o.find("routing_warning");
            if (warning && !warning->asString().empty()) {
                if (!detail.empty()) detail += "；";
                detail += warning->asString();
            }
            SetWindowTextW(row.lblSwitch, switching ? L"" : utf8ToWide(detail).c_str());

            // "测试并连接" completion: when the probed outlet reports ALIVE,
            // flip the config so it becomes the active outlet. Cleared on
            // EVERY outcome so a later click is never swallowed. Never
            // during "switching": the intermediate state carries the STALE
            // node data and must not complete the handshake early.
            if (!pendingOutlet_.empty() && utf8ToWide(pendingOutlet_) == id) {
                const auto* request = o.find("test_request_id");
                const bool matchingRequest = request && request->asString() == pendingTestRequestId_;
                if (switching && (!request || matchingRequest)) pendingOutletStarted_ = true;
                else if (!switching && (matchingRequest || (!request && pendingOutletStarted_))) {
                    const bool selected = !o.find("selection_ok") || o.find("selection_ok")->asBool();
                    const auto tested = pendingOutlet_;
                    pendingOutlet_.clear();
                    pendingOutletStarted_ = false;
                    pendingTestRequestId_.clear();
                    if (api && alive && selected && runtimeMode != "direct" &&
                        !isOutletActive(id)) activateOutletById(tested);
                    updateRadioChecks();
                } else {
                    // A stale result predating this request is not its outcome.
                    SetWindowTextW(row.lblStatus, L"测量中…");
                }
            }
            break;
        }
    }
    // Process liveness and controller visibility are separate facts. A
    // SOCKS-only kernel must not stay in an endless "检测中" placeholder.
    for (const auto& k : kernels_) {
        for (const auto& row : nodeRows_) {
            if (row.outletId != k.id) continue;
            if (!k.alive && k.seen) {
                SetWindowTextW(row.lblStatus, L"内核未启动");
                SetWindowTextW(row.lblSwitch, L"");
                SetWindowTextW(row.lblMetadata, L"");
            } else if (k.alive && !k.hasApi) {
                SetWindowTextW(row.lblStatus, L"内核运行中；节点控制器未识别");
                SetWindowTextW(row.lblSwitch, k.discoveryError.empty()
                    ? L"可检测当前出口的 SOCKS5 端口；节点状态暂不可查询"
                    : k.discoveryError.c_str());
                SetWindowTextW(row.lblMetadata, L"");
            }
        }
    }
}


int MainWindow::layoutNodeRows(int w) {
    if (!nodePane_) return Scaled(120);
    const int right = w - Scaled(4);
    const int btnW = Scaled(170);   // must fit "测试并连接" + radio dot @225% DPI
    const int nameW = Scaled(230);  // show the endpoint beside duplicate names
    const int statusX = Scaled(4) + nameW;
    const int statusW = std::max(Scaled(80), right - statusX - btnW - Scaled(8));
    HDC dc = GetDC(nodePane_);
    const auto oldFont = SelectObject(dc, uiFont());
    auto textHeight = [&](HWND label, int width, int minimum = 0) {
        std::wstring text(static_cast<size_t>(GetWindowTextLengthW(label)) + 1, L'\0');
        const int length = GetWindowTextW(label, text.data(), static_cast<int>(text.size()));
        if (!length) return minimum;
        RECT rect{0, 0, width, 0};
        DrawTextW(dc, text.data(), length, &rect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
        return std::max<int>(minimum, rect.bottom + Scaled(2));
    };
    int y = Scaled(4);
    for (auto& row : nodeRows_) {
        const int firstH = std::max({textHeight(row.lblName, nameW, Scaled(20)),
                                    textHeight(row.lblStatus, statusW, Scaled(20)), Scaled(23)});
        const int metadataH = textHeight(row.lblMetadata, statusW);
        const int detailH = textHeight(row.lblSwitch, statusW);
        const int screenY = y - nodeScrollY_;
        MoveWindow(row.lblName, Scaled(4), screenY, nameW, firstH, FALSE);
        MoveWindow(row.lblStatus, statusX, screenY, statusW, firstH, FALSE);
        MoveWindow(row.btnSpeed, right - btnW, screenY, btnW, Scaled(23), FALSE);
        MoveWindow(row.lblMetadata, statusX, screenY + firstH + Scaled(2), statusW, metadataH, FALSE);
        const int detailY = firstH + (metadataH ? metadataH + Scaled(2) : 0) + Scaled(2);
        MoveWindow(row.lblSwitch, statusX, screenY + detailY, statusW, detailH, FALSE);
        y += detailY + detailH + Scaled(10);
    }
    SelectObject(dc, oldFont);
    ReleaseDC(nodePane_, dc);
    return y;
}

// The ACTIVE outlet's radio stays checked; all others stay unchecked.
// Activation is a single value: routing.autoOutletId ("" = the default
// outlet). Per-outlet enabled flags do NOT imply activation — they only
// govern rules explicitly bound to an outlet.
void MainWindow::updateRadioChecks() {
    const auto& autoId = cfg_.cfg.routing.autoOutletId;
    for (auto& row : nodeRows_) {
        bool active = autoId.empty()
                          ? (row.outletId == L"__default__")
                          : (wideToUtf8(row.outletId) == autoId);
        SendMessageW(row.btnSpeed, BM_SETCHECK, active ? BST_CHECKED : BST_UNCHECKED, 0);
    }
}

// Outlet activation state (mirrors updateRadioChecks).
bool MainWindow::isOutletActive(const std::wstring& outletId) const {
    const auto& autoId = cfg_.cfg.routing.autoOutletId;
    if (autoId.empty()) return outletId == L"__default__";
    return wideToUtf8(outletId) == autoId;
}

// Click semantics:
//  - on an INACTIVE outlet: "测试并连接" — probe, and when alive, activate it
//    (all others deactivated).
//  - on the ACTIVE outlet: re-click means "立即测速并自动切换最优节点" for
//    that outlet (no activation change).
void MainWindow::onSpeedRowClicked(size_t rowIdx) {
    if (!engine_ || !pipeConnected_ || !pendingOutlet_.empty()) return;
    const std::wstring wid = nodeRows_[rowIdx].outletId;
    std::string oid = wideToUtf8(wid);

    // The engine rescans and verifies the current endpoint even when the
    // last UI snapshot has no controller or still says the core is offline.
    // Keep the checked radio on the actual outlet until this test succeeds.
    pendingOutlet_ = oid;
    pendingOutletStarted_ = false;
    UUID token{};
    const auto result = UuidCreate(&token);
    RPC_CSTR encoded=nullptr;
    if ((result == RPC_S_OK || result == RPC_S_UUID_LOCAL_ONLY) && UuidToStringA(&token,&encoded) == RPC_S_OK) {
        pendingTestRequestId_=reinterpret_cast<const char*>(encoded);
        RpcStringFreeA(&encoded);
    } else {
        pendingOutlet_.clear();
        SetWindowTextW(nodeRows_[rowIdx].lblStatus,L"无法建立测试请求标识，请重试");
        return;
    }
    SetWindowTextW(nodeRows_[rowIdx].lblStatus, L"测量中…");
    SetWindowTextW(nodeRows_[rowIdx].lblSwitch, L"");
    if (!engine_->sendNodeSwitch(oid, pendingTestRequestId_)) {
        pendingOutlet_.clear();
        pendingTestRequestId_.clear();
        SetWindowTextW(nodeRows_[rowIdx].lblStatus, L"测试请求未送达，请重试");
    }
}

// Called from the STATUS/STATS handler once an outlet's result is known.
void MainWindow::activateOutletById(const std::string& outletId) {
    // Single source of truth: routing.autoOutletId ("" = default outlet).
    // Choosing the default outlet simply clears it; choosing a discovered
    // kernel id works exactly like a manual outlet. The old code returned
    // early for ids outside the config list, leaving the pending value
    // stuck — which silently swallowed every later click ("无法切回 CFW").
    const bool isDefault = outletId == "__default__";
    bool known = isDefault;
    if (!isDefault) {
        for (const auto& o : cfg_.cfg.outlets) {
            if (o.id == outletId) known = true;
        }
        for (const auto& k : kernels_) {
            if (wideToUtf8(k.id) == outletId) known = true;
        }
    }
    if (!known) return;
    // A manual outlet being activated must also be enabled so rules that
    // explicitly bind to it keep working. Other outlets' enabled flags are
    // left alone: they govern explicit per-rule bindings, not activation.
    if (!isDefault) {
        for (auto& o : cfg_.cfg.outlets) {
            if (o.id == outletId) o.enabled = true;
        }
    }
    cfg_.cfg.routing.autoOutletId = isDefault ? "" : outletId;
    std::string err;
    saveConfig(cfg_, &err);
    if (engine_ && engine_->connected()) engine_->sendReload();
    updateRadioChecks();
    pendingOutlet_.clear();   // handshake done: allow future clicks
}

void MainWindow::toggleAutoSwitch() {
    bool on = SendMessageW(chkAutoSwitch_, BM_GETCHECK, 0, 0) == BST_CHECKED;
    cfg_.cfg.nodeMonitor.enabled = on;
    std::string err;
    saveConfig(cfg_, &err);
    if (engine_ && engine_->connected()) engine_->sendReload();
}

void MainWindow::refreshClassButtonText() {
    std::vector<std::pair<std::string, std::wstring>> items;
    for (size_t i = 0; i < kClassCount; ++i) {
        items.emplace_back(kClasses[i].code, kClasses[i].label);
    }
    for (const auto& g : knownGroups_) {
        items.emplace_back("GROUP:" + wideToUtf8(g), L"分组:" + g);
    }
    std::vector<std::pair<const char*, const wchar_t*>> pitems;
    for (auto& it : items) pitems.emplace_back(it.first.c_str(), it.second.c_str());
    std::wstring text = selectionSummary(cfg_.cfg.nodeMonitor.nodeClasses, pitems);
    SetWindowTextW(btnClass_, text.c_str());
}

void MainWindow::onClassChanged() {
    RECT rc{};
    GetWindowRect(btnClass_, &rc);
    // Fixed classes + the provider's actual groups (membership-based).
    std::vector<std::pair<std::string, std::wstring>> items;
    for (size_t i = 0; i < kClassCount; ++i) {
        items.emplace_back(kClasses[i].code, kClasses[i].label);
    }
    for (const auto& g : knownGroups_) {
        items.emplace_back("GROUP:" + wideToUtf8(g), L"分组:" + g);
    }
    std::vector<std::pair<const char*, const wchar_t*>> pitems;
    for (auto& it : items) pitems.emplace_back(it.first.c_str(), it.second.c_str());
    std::vector<std::string> sel =
        showMultiCheckPopup(hwnd_, rc, pitems, cfg_.cfg.nodeMonitor.nodeClasses);
    if (sel == cfg_.cfg.nodeMonitor.nodeClasses) return;  // dismissed
    cfg_.cfg.nodeMonitor.nodeClasses = sel;
    SetWindowTextW(btnClass_, selectionSummary(sel, pitems).c_str());
    std::string err;
    saveConfig(cfg_, &err);
    for (auto& row : nodeRows_) {
        SetWindowTextW(row.lblStatus, txt::kRegionSwitching);
        SetWindowTextW(row.lblSwitch, L"");
    }
    if (engine_ && engine_->connected()) {
        engine_->sendReload();
        engine_->sendNodeSwitch("");   // immediate re-probe & class-aware re-select
    }
}

void MainWindow::onRegionChanged() {
    RECT rc{};
    GetWindowRect(btnRegion_, &rc);
    std::vector<std::pair<const char*, const wchar_t*>> items;
    for (size_t i = 0; i < kRegionCount; ++i) {
        items.emplace_back(kRegions[i].code, kRegions[i].label);
    }
    std::vector<std::string> sel =
        showMultiCheckPopup(hwnd_, rc, items, cfg_.cfg.nodeMonitor.regions);
    if (sel == cfg_.cfg.nodeMonitor.regions) return;  // dismissed
    cfg_.cfg.nodeMonitor.regions = sel;
    SetWindowTextW(btnRegion_, selectionSummary(sel, items).c_str());
    std::string err;
    saveConfig(cfg_, &err);
    // Immediate visual feedback: measurement takes a few seconds even with
    // the parallel probing — the rows must SAY they are switching instead of
    // silently showing the old node (measured: users read 30s of stale
    // "香港" as "region selection doesn't work").
    for (auto& row : nodeRows_) {
        SetWindowTextW(row.lblStatus, txt::kRegionSwitching);
        SetWindowTextW(row.lblSwitch, L"");
    }
    if (engine_ && engine_->connected()) {
        engine_->sendReload();
        // Immediate feedback: re-probe every outlet and re-select in-region.
        engine_->sendNodeSwitch("");
    }
}

LRESULT MainWindow::wndProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Critical: WM_NCCREATE arrives BEFORE CreateWindowExW returns, so the
    // hwnd_ member is still null. Adopt the OS-provided handle first, or
    // every child creation and DefWindowProc call below would use null and
    // silently abort window creation.
    hwnd_ = wnd;
    if (taskbarCreatedMsg_ != 0 && msg == taskbarCreatedMsg_) {
        const bool restored = tray_.restoreAfterTaskbarRestart();
        guiDiagStep(restored ? "tray: restored after Explorer restart"
                             : "tray: RESTORE AFTER EXPLORER RESTART FAILED");
        if (restored) {
            log::i("tray icon restored after Explorer restart");
        } else {
            log::w("failed to restore tray icon after Explorer restart");
        }
        return 0;
    }
    switch (msg) {
        case WM_CREATE:
            // Adopt the window's true monitor DPI before laying out children.
            setLayoutDpi(GetDpiForWindow(hwnd_));
            buildUi();
            // Outer size was computed before the window existed (system DPI);
            // re-fit it to the now-known per-monitor DPI.
            {
                MONITORINFO monitor{sizeof(monitor)};
                GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST), &monitor);
                SetWindowPos(hwnd_, nullptr, monitor.rcWork.left, monitor.rcWork.top,
                    std::min<int>(Scaled(1010), monitor.rcWork.right - monitor.rcWork.left),
                    std::min<int>(Scaled(900), monitor.rcWork.bottom - monitor.rcWork.top),
                    SWP_NOZORDER);
            }
            return 0;
        case WM_DPICHANGED: {
            // Monitor DPI changed (drag to another screen): rescale the whole
            // layout by rebuilding the children at the new factor.
            setLayoutDpi(GetDpiForWindow(hwnd_));
            EnumChildWindows(hwnd_, [](HWND h, LPARAM) -> BOOL {
                DestroyWindow(h);
                return TRUE;
            }, 0);
            // The HWNDs and rendered-connection cache belonged to the
            // destroyed controls, not to the unchanged engine/config data.
            // Invalidate them BEFORE new controls can reuse old HWND values.
            nodeRows_.clear();
            lastConnsJson_.clear();
            buildUi();
            auto* suggested = reinterpret_cast<RECT*>(lp);
            SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        case WM_SIZE:
            layout(LOWORD(lp), HIWORD(lp));
            // Minimize/restore changes the STATS-consumer state too.
            updateStatsVisibility();
            return 0;
        case WM_VSCROLL: scrollPage(SB_VERT, LOWORD(wp)); return 0;
        case WM_HSCROLL: scrollPage(SB_HORZ, LOWORD(wp)); return 0;
        case WM_MOUSEWHEEL:
            scrollPage(SB_VERT, -1, -GET_WHEEL_DELTA_WPARAM(wp) * Scaled(60) / WHEEL_DELTA);
            return 0;
        case WM_SHOWWINDOW:
            updateStatsVisibility();   // tray hide / restore
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = Scaled(540);
            mmi->ptMinTrackSize.y = Scaled(360);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            switch (id) {
                case IDC_BTN_START: startEngineFromUi(); return 0;
                case IDC_BTN_STOP: stopEngineFromUi(true); return 0;
                case IDC_BTN_TEST: testProxyAsync(); return 0;
                case IDC_BTN_SAVE_PROXY: applyProxySettingsFromUi(); return 0;
                case IDC_BTN_OFFLINE:
                    showOffline_ = !showOffline_;
                    refreshNodeStatus(lastEngineOutlets_, nullptr);
                    return 0;
                case IDC_BTN_ADD:
                case IDC_BTN_BROWSE: {
                    Rule empty;
                    auto r = showRuleEditDialog(hwnd_, nullptr, &cfg_.cfg.outlets);
                    if (r) addRuleFromPath(utf8ToWide(r->path), nullptr, &*r);
                    return 0;
                }
                case IDC_BTN_PICK: {
                    auto path = showPickProcessDialog(hwnd_);
                    if (path) addRuleFromPath(*path, nullptr);
                    return 0;
                }
                case IDC_BTN_FLUSH:
                    if (engine_ && engine_->connected()) engine_->sendFlush("");
                    return 0;
                case IDC_BTN_EXPORT: exportConfigUi(); return 0;
                case IDC_BTN_IMPORT: importConfigUi(); return 0;
                case IDC_BTN_CLEARLOG: clearLogs(); return 0;
                case IDC_BTN_ABOUT: showAboutDialog(hwnd_); return 0;
                case IDC_BTN_OUTLETS: {
                    auto outlets = cfg_.cfg.outlets;
                    if (showOutletsDialog(hwnd_, outlets)) {
                        cfg_.cfg.outlets = std::move(outlets);
                        // Hand-edited activation state supersedes the
                        // single-outlet override (otherwise the engine keeps
                        // routing by autoOutletId and the dialog's enabled
                        // checkboxes would appear to have no effect).
                        cfg_.cfg.routing.autoOutletId.clear();
                        std::string err;
                        saveConfig(cfg_, &err);
                        if (engine_ && engine_->connected()) engine_->sendReload();
                        // The user just set the activation state BY HAND; a
                        // stale pendingOutlet_ from an earlier speed-test
                        // click must not overwrite it when a delayed status
                        // push arrives.
                        pendingOutlet_.clear();
                    }
                    updateRadioChecks();
                    return 0;
                }
                case IDC_BTN_NODESWITCH:
                    if (engine_ && engine_->connected()) engine_->sendNodeSwitch("");
                    return 0;
                case IDC_CHK_AUTOSWITCH:
                    toggleAutoSwitch();
                    return 0;
                case IDC_CHK_COVERDIR: {
                    bool on = SendMessageW(chkCoverDir_, BM_GETCHECK, 0, 0) ==
                              BST_CHECKED;
                    cfg_.cfg.routing.coverAppDirAlways = on;
                    std::string cerr;
                    saveConfig(cfg_, &cerr);
                    if (engine_ && engine_->connected()) engine_->sendReload();
                    return 0;
                }
                case IDC_CHK_DNSCLEAN: {
                    bool on = SendMessageW(chkDnsClean_, BM_GETCHECK, 0, 0) ==
                              BST_CHECKED;
                    cfg_.cfg.routing.dnsCleanup = on;
                    std::string cerr;
                    saveConfig(cfg_, &cerr);
                    if (engine_ && engine_->connected()) engine_->sendReload();
                    return 0;
                }
                case IDC_COMBO_REGION:
                    onRegionChanged();
                    return 0;
                case IDC_COMBO_CLASS:
                    onClassChanged();
                    return 0;
                case IDC_BTN_SUBREFRESH:
                    if (engine_ && engine_->connected()) {
                        SetWindowTextW(btnSubRefresh_, txt::kSubRefreshing);
                        engine_->sendSubRefresh();
                    }
                    return 0;
                default: {
                    size_t rowIdx = -1;
                    if (id >= IDC_BTN_SPEED_ROW &&
                        static_cast<size_t>(id - IDC_BTN_SPEED_ROW) < nodeRows_.size()) {
                        rowIdx = size_t(id - IDC_BTN_SPEED_ROW);
                        if (rowIdx < nodeRows_.size()) onSpeedRowClicked(rowIdx);
                    }
                    return 0;
                }
            }
        }
        case WM_NOTIFY:
            rules_.handleNotify(reinterpret_cast<LPNMHDR>(lp));
            conns_.handleNotify(reinterpret_cast<LPNMHDR>(lp));
            return 0;
        case WM_APP_TRAY:
            onTrayEvent(lp);
            return 0;
        case WM_APP_PIPE_MSG: {
            auto* s = reinterpret_cast<std::string*>(lp);
            onPipeMessage(*s);
            delete s;
            return 0;
        }
        case WM_APP_PIPE_STATE:
            onPipeState(wp != 0);
            return 0;
        case WM_APP_PROXY_TEST: {
            auto* s = reinterpret_cast<std::string*>(lp);
            std::string detail = s->substr(s->find('|') + 1);
            if (proxyTestThread_.joinable()) proxyTestThread_.join();
            if (wp == proxyTestGeneration_) onProxyTestResult(s->starts_with("OK|"), detail);
            delete s;
            EnableWindow(btnTest_, !proxyTargetKey().empty());
            return 0;
        }
        case WM_CLOSE: {
            ShowWindow(hwnd_, SW_HIDE);  // close-to-tray
            updateStatsVisibility();     // stop the per-second STATS push
            static bool balloonShown = false;
            if (!balloonShown) {
                balloonShown = true;
                tray_.showBalloon(txt::kAppTitle,
                                  L"程序仍在后台运行（右下角托盘）。双击托盘图标可"
                                  L"重新打开；右键可选退出。");
            }
            return 0;
        }
        case WM_DESTROY:
            if (proxyTestThread_.joinable()) proxyTestThread_.join();
            {
                MSG pending{};
                while (PeekMessageW(&pending, hwnd_, WM_APP_PROXY_TEST, WM_APP_PROXY_TEST, PM_REMOVE))
                    delete reinterpret_cast<std::string*>(pending.lParam);
            }
            tray_.remove();
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd_, msg, wp, lp);
    }
}

}  // namespace aps::gui
