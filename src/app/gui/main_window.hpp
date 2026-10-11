// Main window: engine controls, proxy settings, rules list, tray, IPC wiring.
#pragma once

#include <windows.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "connections_view.hpp"
#include "engine_client.hpp"
#include "gui_config.hpp"
#include "rules_view.hpp"
#include "tray.hpp"

namespace aps::gui {

class MainWindow {
public:
    static MainWindow* create(HINSTANCE inst);

    HWND hwnd() const { return hwnd_; }
    LRESULT wndProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp);

    void onTrayEvent(LPARAM lParam);
    void onPipeMessage(const std::string& jsonLine);
    void onPipeState(bool connected);
    void onProxyTestResult(bool ok, const std::string& detail);

    void startEngineFromUi();

private:
    void buildUi();
    void layout(int w, int h);
    void scrollPage(int bar, int code, int position = 0);
    void scrollNodes(int code, int position = 0);
    static LRESULT CALLBACK nodePaneProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp,
                                         UINT_PTR subclass, DWORD_PTR context);
    void refreshEffectiveProxy(const json::Value* proxy);
    void refreshRules();
    void refreshStatusText();
    void applyProxySettingsFromUi();
    void testProxyAsync();
    void addRuleFromPath(const std::wstring& path, const wchar_t* name,
                         const Rule* fromDialog = nullptr);
    void deleteRuleUi(const std::string& ruleId);
    void editRuleUi(const std::string& ruleId);
    void toggleRule(const std::string& ruleId, bool enabled);
    void stopEngineFromUi(bool confirm);
    void clearLogs();
    void exitApp();
    void exportConfigUi();
    void importConfigUi();

    HWND hwnd_ = nullptr;
    HINSTANCE inst_ = nullptr;
    UINT taskbarCreatedMsg_ = 0;
    GuiConfigState cfg_;
    RulesView rules_;
    ConnectionsView conns_;
    TrayIcon tray_;
    std::unique_ptr<EngineClient> engine_;

    // Controls
    HWND btnStart_ = nullptr, btnStop_ = nullptr;
    HWND lblState_ = nullptr, lblAdmin_ = nullptr;
    HWND editHost_ = nullptr, editPort_ = nullptr, editUser_ = nullptr,
         editPass_ = nullptr, editApiSecret_ = nullptr;
    HWND btnTest_ = nullptr, lblTestResult_ = nullptr;
    HWND lblEffectiveProxy_ = nullptr, btnOffline_ = nullptr;
    HWND nodePane_ = nullptr;
    struct FixedControl { HWND hwnd; RECT rect; };
    std::vector<FixedControl> fixedControls_;
    int scrollX_ = 0, scrollY_ = 0;
    int nodeScrollY_ = 0;
    bool layingOut_ = false, showOffline_ = false;
    size_t offlineCount_ = 0;
    json::Value lastEngineOutlets_ = json::Value::makeArray();
    json::Value effectiveProxy_ = json::Value::makeObject();
    std::string proxyTestKey_, proxyTestDetail_;
    uintptr_t proxyTestGeneration_ = 0;
    std::thread proxyTestThread_;
    std::string proxyTargetKey() const;
    HWND btnAdd_ = nullptr, btnPick_ = nullptr, btnBrowse_ = nullptr,
         btnFlush_ = nullptr, btnClearLog_ = nullptr, btnAbout_ = nullptr;
    HWND lblNotice_ = nullptr;
    HWND lblNodeTitle_ = nullptr, chkAutoSwitch_ = nullptr, btnOutlets_ = nullptr;
    HWND lblConns_ = nullptr, btnExport_ = nullptr, btnImport_ = nullptr;
    HWND lblRegion_ = nullptr, btnRegion_ = nullptr;
    HWND lblClass_ = nullptr, btnClass_ = nullptr;
    HWND chkCoverDir_ = nullptr;
    HWND chkDnsClean_ = nullptr;
    HWND btnSubRefresh_ = nullptr;
    // True while the ENGINE reports sub_refresh == "running". The button
    // text and the completion popup follow this flag — the engine is the
    // authority, not the click. A popup fires exactly once per cycle (on
    // the running -> result transition), so identical consecutive results
    // still get feedback (the old string-dedupe swallowed a repeated
    // "限流" error and the button stuck at 刷新中 forever).
    bool subRefreshActive_ = false;
    // Provider group names (from the engine's outlets pushes): offered as
    // "分组:xxx" entries in the class popup (group-membership classes).
    std::vector<std::wstring> knownGroups_;
    void refreshClassButtonText();
    // Per-outlet node status rows: name label, status text (line 1), the
    // "上次切换" detail on its OWN line (line 2), and a "测速" button.
    struct NodeRow {
        HWND lblName = nullptr;
        HWND lblStatus = nullptr;
        HWND lblMetadata = nullptr;
        HWND lblSwitch = nullptr;
        HWND btnSpeed = nullptr;
        std::wstring outletId;
    };
    std::vector<NodeRow> nodeRows_;
    // Auto-discovered kernels from the engine's "kernels" pushes:
    // (id "auto-<proc>", display name, alive). Rows survive engine restarts;
    // offline kernels keep their row with status "已停止".
    struct KernelRow {
        std::wstring id;
        std::wstring name;
        std::wstring procName;
        bool alive = true;
        std::wstring discoveryError;
        bool hasApi = false;   // controller port found (probe-able)
        // Confirmed by a completed engine scan (found OR confirmed missing).
        // Unverified rows are the brief post-start window: clicks must run
        // a probe, not show a blocking "not started" dialog.
        bool seen = false;
    };
    std::vector<KernelRow> kernels_;
    void refreshNodeStatus(const json::Value& outlets, const json::Value* kernels);
    void ensureRowsFromConfig();          // rows exist as soon as UI opens
    void applyEngineData(const json::Value& engineOutlets);
    int layoutNodeRows(int w);
    void toggleAutoSwitch();
    void onRegionChanged();
    void onClassChanged();
    void updateRadioChecks();
    void onSpeedRowClicked(size_t rowIdx);
    void activateOutletById(const std::string& outletId);
    bool isOutletActive(const std::wstring& outletId) const;
    // Outlet awaiting "tested AND alive" before activation ("" = none).
    // Single value, cleared on EVERY outcome (alive, unreachable, user edit).
    std::string pendingOutlet_;
    bool pendingOutletStarted_ = false;
    std::string pendingTestRequestId_;

    std::string engineState_ = "STOPPED";
    bool pipeConnected_ = false;
    std::atomic<bool> engineLaunching_{false};
    // Last rendered connections payload: identical payloads skip the
    // per-second ListView repopulation (power saving).
    std::string lastConnsJson_;
    // Last visibility state sent to the engine (gates the 1s STATS push).
    bool statsVisSent_ = true;
    void updateStatsVisibility();
};

}  // namespace aps::gui
