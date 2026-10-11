// ConnectionsView ("活动连接") population: full-repopulate semantics with
// no user interactions (read-only list). Mirrors test_rules_view's hidden
// parent window setup.
#include <windows.h>
#include <commctrl.h>
#include <algorithm>

#include "connections_view.hpp"
#include "testlib/appsw_test.h"

using namespace aps::gui;

namespace {
struct CtlInit {
    CtlInit() {
        INITCOMMONCONTROLSEX icc{};
        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icc);
    }
};
CtlInit g_ctl;

ConnectionsView* g_forwardTo = nullptr;
LRESULT CALLBACK parentProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NOTIFY && g_forwardTo) {
        g_forwardTo->handleNotify(reinterpret_cast<LPNMHDR>(lp));
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}
}  // namespace

APS_TEST(connsview, set_connections_populates_rows) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = parentProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"ApsConnsViewTestParent";
    RegisterClassW(&wc);
    HWND parent = CreateWindowExW(0, wc.lpszClassName, L"t", WS_OVERLAPPEDWINDOW, 0, 0,
                                  800, 600, nullptr, nullptr, wc.hInstance, nullptr);
    EXPECT_TRUE(parent != nullptr);
    ShowWindow(parent, SW_HIDE);

    ConnectionsView view;
    g_forwardTo = &view;
    EXPECT_TRUE(view.create(parent, wc.hInstance, 0, 0, 780, 500));

    std::vector<ConnectionsView::ConnRow> rows;
    for (int i = 0; i < 5; ++i) {
        ConnectionsView::ConnRow r;
        r.proc = L"C:\\Apps\\app" + std::to_wstring(i) + L".exe";
        r.target = L"1.2.3.4:443";
        r.ruleName = L"rule" + std::to_wstring(i);
        r.outletName = L"默认出口";
        r.state = L"已建立";
        r.host = L"example.com";
        r.bytesUp = 1024;
        r.bytesDown = 2048;
        r.durationMs = 90000;
        rows.push_back(std::move(r));
    }
    view.setConnections(rows);
    EXPECT_EQ(ListView_GetItemCount(view.hwnd()), 5);

    wchar_t buf[256];
    ListView_GetItemText(view.hwnd(), 0, 0, buf, 256);   // proc column = basename
    EXPECT_TRUE(std::wstring(buf) == L"app0.exe");
    ListView_GetItemText(view.hwnd(), 0, 1, buf, 256);   // target
    EXPECT_TRUE(std::wstring(buf) == L"1.2.3.4:443");
    ListView_GetItemText(view.hwnd(), 0, 4, buf, 256);   // duration "1 分 30 秒"
    EXPECT_TRUE(std::wstring(buf) == L"1 分 30 秒");

    // A live snapshot reorders flows by last activity. Keep the viewed flow
    // and selection anchored while byte counters and sorting change.
    rows.clear();
    for (int i = 0; i < 80; ++i) {
        ConnectionsView::ConnRow r;
        r.key = L"flow-" + std::to_wstring(i);
        r.proc = L"C:\\Apps\\app.exe";
        r.target = r.key;
        rows.push_back(r);
    }
    view.setConnections(rows);
    RECT item{};
    ListView_GetItemRect(view.hwnd(), 0, &item, LVIR_BOUNDS);
    ListView_Scroll(view.hwnd(), 100, 25 * (item.bottom - item.top));
    const int oldTop = ListView_GetTopIndex(view.hwnd());
    const int oldHorizontal = GetScrollPos(view.hwnd(), SB_HORZ);
    EXPECT_GT(oldTop, 10);
    const std::wstring anchor = rows[oldTop].key;
    ListView_SetItemState(view.hwnd(), 35, LVIS_SELECTED, LVIS_SELECTED);
    const std::wstring selected = rows[35].key;
    std::rotate(rows.begin(), rows.begin() + 10, rows.end());
    for (auto& r : rows) r.bytesUp += 1000;
    view.setConnections(rows);
    EXPECT_TRUE(rows[ListView_GetTopIndex(view.hwnd())].key == anchor);
    EXPECT_TRUE(rows[ListView_GetNextItem(view.hwnd(), -1, LVNI_SELECTED)].key == selected);
    EXPECT_EQ(GetScrollPos(view.hwnd(), SB_HORZ), oldHorizontal);

    // Full repopulate replaces everything (engine pushes a fresh snapshot
    // every second; stale rows must never linger).
    view.setConnections({});
    EXPECT_EQ(ListView_GetItemCount(view.hwnd()), 0);

    DestroyWindow(parent);
}

APS_TEST_MAIN();
