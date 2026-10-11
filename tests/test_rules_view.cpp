// Regression test for the "opening the GUI silently disables every rule" bug:
// Windows ListView fires LVN_ITEMCHANGED for programmatic InsertItem /
// SetCheckState calls (new rows start UNCHECKED), which the old code mistook
// for the user unchecking rules and persisted enabled=false to config.
#include <windows.h>
#include <commctrl.h>

#include <atomic>

#include "rules_view.hpp"
#include "testlib/appsw_test.h"

using namespace aps::gui;

namespace {
struct WsaInit {
    WsaInit() {
        INITCOMMONCONTROLSEX icc{};
        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icc);
    }
};
WsaInit g_ctl;

// Parent window that forwards WM_NOTIFY to the view under test, exactly like
// MainWindow does in production.
RulesView* g_forwardTo = nullptr;
LRESULT CALLBACK parentProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NOTIFY && g_forwardTo) {
        g_forwardTo->handleNotify(reinterpret_cast<LPNMHDR>(lp));
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}
}  // namespace

APS_TEST(rulesview, set_rules_does_not_fire_toggle) {
    // Hidden parent window (window station quirks aside, CreateWindowExW
    // works from test processes too).
    WNDCLASSW wc{};
    wc.lpfnWndProc = parentProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"ApsRulesViewTestParent";
    RegisterClassW(&wc);
    HWND parent = CreateWindowExW(0, wc.lpszClassName, L"t", WS_OVERLAPPEDWINDOW, 0, 0,
                                  800, 600, nullptr, nullptr, wc.hInstance, nullptr);
    EXPECT_TRUE(parent != nullptr);
    ShowWindow(parent, SW_HIDE);

    RulesView view;
    g_forwardTo = &view;
    std::atomic<int> toggles{0};
    RulesView::Callbacks cbs;
    cbs.onToggle = [&](const std::string&, bool) { toggles.fetch_add(1); };
    cbs.onEdit = [](const std::string&) {};
    cbs.onDelete = [](const std::string&) {};
    view.setCallbacks(std::move(cbs));
    EXPECT_TRUE(view.create(parent, wc.hInstance, 0, 0, 780, 500));

    std::vector<RulesView::RuleRow> rows;
    for (int i = 0; i < 3; ++i) {
        RulesView::RuleRow r;
        r.ruleId = "rule-" + std::to_string(i);
        r.enabled = true;  // the critical case: enabled rules must stay enabled
        r.path = L"C:\\Apps\\app" + std::to_wstring(i) + L".exe";
        r.name = L"app" + std::to_wstring(i);
        rows.push_back(std::move(r));
    }
    view.setRules(rows);

    // Pump window messages so any spurious LVN_ITEMCHANGED would land.
    MSG msg;
    for (int i = 0; i < 50; ++i) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }

    // The regression: populating the list must NOT be interpreted as the
    // user toggling rules.
    EXPECT_EQ(toggles.load(), 0);

    // Sanity: a genuine user-style check-state change DOES fire the callback.
    ListView_SetCheckState(view.hwnd(), 0, FALSE);
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    Sleep(50);
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    EXPECT_EQ(toggles.load(), 1);

    DestroyWindow(parent);
}

APS_TEST_MAIN();
