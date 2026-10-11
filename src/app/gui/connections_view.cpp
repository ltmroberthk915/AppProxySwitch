#include "connections_view.hpp"
#include <algorithm>

#include "aps/path_util.hpp"
#include "app.hpp"
#include "i18n.hpp"

namespace aps::gui {

namespace {
// Control id; RulesView uses 1001.
constexpr int kConnListId = 1002;
enum Col {
    kColProc = 0, kColTarget, kColRule, kColOutlet, kColDuration,
    kColUp, kColDown, kColHost, kColState, kColCount
};
constexpr int kColWidths[] = {150, 150, 100, 80, 60, 75, 75, 190, 60};
}  // namespace

bool ConnectionsView::create(HWND parent, HINSTANCE inst, int x, int y, int w, int h) {
    hwnd_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER |
                                WS_VSCROLL | WS_HSCROLL | LVS_REPORT |
                                LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                            x, y, w, h, parent,
                            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kConnListId)),
                            inst, nullptr);
    if (!hwnd_) return false;
    ListView_SetExtendedListViewStyle(hwnd_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                                 LVS_EX_LABELTIP);

    const wchar_t* titles[kColCount] = {
        txt::kColProc, txt::kColTarget, txt::kColRule, txt::kColOutlet,
        txt::kColDuration, txt::kColUp, txt::kColDown, txt::kColHost, txt::kColState};
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < kColCount; ++i) {
        col.pszText = const_cast<LPWSTR>(titles[i]);
        col.cx = Scaled(kColWidths[i]);
        ListView_InsertColumn(hwnd_, i, &col);
    }
    SendMessageW(hwnd_, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
    return true;
}

std::wstring ConnectionsView::humanBytes(uint64_t n) const {
    wchar_t buf[32];
    if (n >= 1ull << 30) swprintf_s(buf, L"%.1f GB", n / 1073741824.0);
    else if (n >= 1ull << 20) swprintf_s(buf, L"%.1f MB", n / 1048576.0);
    else if (n >= 1024) swprintf_s(buf, L"%.1f KB", n / 1024.0);
    else swprintf_s(buf, L"%llu B", static_cast<unsigned long long>(n));
    return buf;
}

std::wstring ConnectionsView::humanDuration(int64_t ms) const {
    wchar_t buf[32];
    if (ms < 0) ms = 0;
    int64_t s = ms / 1000;
    if (s < 60) {
        swprintf_s(buf, L"%lld 秒", static_cast<long long>(s));
    } else {
        swprintf_s(buf, L"%lld 分 %lld 秒", static_cast<long long>(s / 60),
                   static_cast<long long>(s % 60));
    }
    return buf;
}

void ConnectionsView::setConnections(const std::vector<ConnRow>& rows) {
    building_ = true;
    const int top = ListView_GetTopIndex(hwnd_);
    const int selected = ListView_GetNextItem(hwnd_, -1, LVNI_SELECTED);
    const int horizontal = GetScrollPos(hwnd_, SB_HORZ);
    const std::wstring anchor = top >= 0 && top < static_cast<int>(rows_.size())
                                    ? rows_[top].key : L"";
    const std::wstring selection = selected >= 0 && selected < static_cast<int>(rows_.size())
                                    ? rows_[selected].key : L"";
    SendMessageW(hwnd_, WM_SETREDRAW, FALSE, 0);
    rows_ = rows;
    ListView_DeleteAllItems(hwnd_);
    auto setCell = [&](int item, int col, const std::wstring& text) {
        ListView_SetItemText(hwnd_, item, col, const_cast<LPWSTR>(text.c_str()));
    };
    for (size_t i = 0; i < rows_.size(); ++i) {
        const ConnRow& r = rows_[i];
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = static_cast<int>(i);
        std::wstring proc = r.proc;
        it.pszText = proc.data();
        it.lParam = static_cast<LPARAM>(i);
        ListView_InsertItem(hwnd_, &it);
        setCell(static_cast<int>(i), kColProc, baseName(r.proc));
        setCell(static_cast<int>(i), kColTarget, r.target);
        setCell(static_cast<int>(i), kColRule, r.ruleName);
        setCell(static_cast<int>(i), kColOutlet, r.outletName);
        setCell(static_cast<int>(i), kColDuration, humanDuration(r.durationMs));
        setCell(static_cast<int>(i), kColUp, humanBytes(r.bytesUp));
        setCell(static_cast<int>(i), kColDown, humanBytes(r.bytesDown));
        setCell(static_cast<int>(i), kColHost, r.host.empty() ? std::wstring(L"-") : r.host);
        setCell(static_cast<int>(i), kColState, r.state);
    }
    int restoreTop = std::min(top, static_cast<int>(rows_.size()) - 1);
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (!anchor.empty() && rows_[i].key == anchor) restoreTop = static_cast<int>(i);
        if (!selection.empty() && rows_[i].key == selection)
            ListView_SetItemState(hwnd_, static_cast<int>(i), LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
    }
    RECT item{};
    if (restoreTop >= 0 && ListView_GetItemRect(hwnd_, 0, &item, LVIR_BOUNDS))
        ListView_Scroll(hwnd_, 0,
                        (restoreTop - ListView_GetTopIndex(hwnd_)) * (item.bottom - item.top));
    SendMessageW(hwnd_, WM_SETREDRAW, TRUE, 0);
    // Comctl32 rebuilds horizontal ranges when redraw resumes.
    ListView_Scroll(hwnd_, horizontal - GetScrollPos(hwnd_, SB_HORZ), 0);
    InvalidateRect(hwnd_, nullptr, TRUE);
    building_ = false;
}

void ConnectionsView::handleNotify(LPNMHDR nm) {
    if (nm->idFrom != kConnListId) return;
    (void)nm;  // read-only list: no interactions
}

}  // namespace aps::gui
