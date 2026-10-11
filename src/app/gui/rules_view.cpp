#include "rules_view.hpp"

#include <windowsx.h>
#include <shellapi.h>

#include "aps/path_util.hpp"
#include "aps/string_util.hpp"
#include "app.hpp"
#include "i18n.hpp"

namespace aps::gui {

namespace {
enum Col {
    kColEnabled = 0, kColIcon, kColName, kColPath, kColPid, kColConns,
    kColBlocked, kColTraffic, kColError, kColAction, kColCount
};
constexpr int kColWidths[] = {44, 30, 130, 260, 70, 60, 56, 130, 180, 90};
}  // namespace

bool RulesView::create(HWND parent, HINSTANCE inst, int x, int y, int w, int h) {
    hwnd_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER |
                                WS_VSCROLL | WS_HSCROLL | LVS_REPORT |
                                LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                            x, y, w, h, parent, reinterpret_cast<HMENU>(1001), inst,
                            nullptr);
    if (!hwnd_) return false;
    ListView_SetExtendedListViewStyle(hwnd_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                                 LVS_EX_LABELTIP | LVS_EX_CHECKBOXES);

    const wchar_t* titles[kColCount] = {
        txt::kColEnabled, L"", txt::kColName, txt::kColPath, txt::kColPid,
        txt::kColConns, txt::kColBlocked, txt::kColTraffic, txt::kColError,
        txt::kColAction};
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    for (int i = 0; i < kColCount; ++i) {
        col.pszText = const_cast<LPWSTR>(titles[i]);
        col.cx = Scaled(kColWidths[i]);
        ListView_InsertColumn(hwnd_, i, &col);
    }

    icons_ = ImageList_Create(GetSystemMetrics(SM_CXSMICON),
                              GetSystemMetrics(SM_CYSMICON), ILC_COLOR32 | ILC_MASK, 16,
                              16);
    ListView_SetImageList(hwnd_, icons_, LVSIL_SMALL);
    SendMessageW(hwnd_, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont()), TRUE);
    return true;
}

int RulesView::rowOf(const std::string& ruleId) const {
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (rows_[i].ruleId == ruleId) return static_cast<int>(i);
    }
    return -1;
}

void RulesView::setRules(const std::vector<RuleRow>& rows) {
    building_ = true;
    rows_ = rows;
    ListView_DeleteAllItems(hwnd_);
    for (size_t i = 0; i < rows_.size(); ++i) {
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        it.iItem = static_cast<int>(i);
        std::wstring dash = L"-";
        it.pszText = dash.data();
        it.iImage = -1;
        it.lParam = static_cast<LPARAM>(i);
        ListView_InsertItem(hwnd_, &it);
        ListView_SetCheckState(hwnd_, static_cast<int>(i), rows_[i].enabled);
        refreshRow(static_cast<int>(i));
    }
    building_ = false;
}

void RulesView::updateLiveData(const std::string& ruleId, uint32_t pid, uint64_t conns,
                               uint64_t blocked, uint64_t up, uint64_t down,
                               const std::wstring& lastError) {
    int i = rowOf(ruleId);
    if (i < 0) return;
    rows_[i].lastPid = pid;
    rows_[i].conns = conns;
    rows_[i].blocked = blocked;
    rows_[i].bytesUp = up;
    rows_[i].bytesDown = down;
    if (!lastError.empty()) rows_[i].lastError = lastError;
    else rows_[i].lastError.clear();
    refreshRow(i);
}

std::wstring RulesView::humanBytes(uint64_t n) const {
    wchar_t buf[32];
    if (n >= 1ull << 30) swprintf_s(buf, L"%.1f GB", n / 1073741824.0);
    else if (n >= 1ull << 20) swprintf_s(buf, L"%.1f MB", n / 1048576.0);
    else if (n >= 1024) swprintf_s(buf, L"%.1f KB", n / 1024.0);
    else swprintf_s(buf, L"%llu B", static_cast<unsigned long long>(n));
    return buf;
}

void RulesView::refreshRow(int i) {
    // Called from the per-second STATS handler too; keep programmatic
    // check-state changes silent the same way setRules does.
    bool prev = building_;
    building_ = true;
    const RuleRow& r = rows_[i];
    auto setCell = [&](int col, const std::wstring& text) {
        ListView_SetItemText(hwnd_, i, col, const_cast<LPWSTR>(text.c_str()));
    };
    // Icon: file-specific icon, cached by extension+path.
    int image = -1;
    std::wstring key = aps::canonicalPathKey(r.path);
    auto cached = iconCache_.find(key);
    if (cached != iconCache_.end()) {
        image = cached->second;
    } else {
        SHFILEINFOW sfi{};
        if (SHGetFileInfoW(r.path.c_str(), 0, &sfi, sizeof(sfi),
                           SHGFI_ICON | SHGFI_SMALLICON | SHGFI_OPENICON)) {
            if (sfi.hIcon) {
                // SHGetFileInfoW returns a SHARED system icon: DestroyIcon on
                // it corrupts the system icon cache (observable as the
                // taskbar / system scaling glitch). ImageList_ReplaceIcon
                // copies it, which is all we need.
                image = ImageList_ReplaceIcon(icons_, -1, sfi.hIcon);
            }
        }
        if (iconCache_.size() > 256) iconCache_.clear();
        iconCache_[key] = image;
    }
    LVITEMW it{};
    it.mask = LVIF_IMAGE;
    it.iItem = i;
    it.iImage = image;
    ListView_SetItem(hwnd_, &it);

    setCell(kColName, r.name.empty() ? r.path : r.name);
    setCell(kColPath, r.path);
    setCell(kColPid, r.lastPid ? std::to_wstring(r.lastPid) : std::wstring(L"-"));
    setCell(kColConns, std::to_wstring(r.conns));
    setCell(kColBlocked, r.blocked ? std::to_wstring(r.blocked) : std::wstring(L"-"));
    setCell(kColTraffic, humanBytes(r.bytesUp) + L" / " + humanBytes(r.bytesDown));
    setCell(kColError, r.lastError.empty() ? std::wstring(L"-") : r.lastError);
    setCell(kColAction, std::wstring(txt::kEditRule) + L" | " + txt::kDeleteRule);
    ListView_SetCheckState(hwnd_, i, r.enabled);
    building_ = prev;
}

void RulesView::handleNotify(LPNMHDR nm) {
    if (nm->idFrom != 1001) return;
    if (nm->code == LVN_ITEMCHANGED) {
        if (building_) return;  // programmatic population, not a user click
        auto* p = reinterpret_cast<NMLISTVIEW*>(nm);
        if ((p->uNewState & LVIS_STATEIMAGEMASK) != 0 &&
            (p->uOldState & LVIS_STATEIMAGEMASK) !=
                (p->uNewState & LVIS_STATEIMAGEMASK) &&
            p->iItem >= 0 && p->iItem < static_cast<int>(rows_.size())) {
            // Suppress the echo of our own SetCheckState in refreshRow.
            BOOL now = ListView_GetCheckState(hwnd_, p->iItem);
            if (now != FALSE && rows_[p->iItem].enabled) return;
            if (now == FALSE && !rows_[p->iItem].enabled) return;
            rows_[p->iItem].enabled = now != FALSE;
            if (cbs_.onToggle) cbs_.onToggle(rows_[p->iItem].ruleId, now != FALSE);
        }
    } else if (nm->code == NM_CLICK || nm->code == NM_DBLCLK) {
        auto* p = reinterpret_cast<NMITEMACTIVATE*>(nm);
        if (p->iItem < 0 || p->iItem >= static_cast<int>(rows_.size())) return;
        // Locate the clicked subitem (the ListView itself only reports the
        // item; approximate via hit test).
        DWORD pos = GetMessagePos();
        POINT pt{GET_X_LPARAM(pos), GET_Y_LPARAM(pos)};
        ScreenToClient(hwnd_, &pt);
        LVHITTESTINFO ht{};
        ht.pt = pt;
        int sub = ListView_SubItemHitTest(hwnd_, &ht);
        if (sub == kColAction || nm->code == NM_DBLCLK) {
            RECT rc{};
            if (ListView_GetSubItemRect(hwnd_, p->iItem, kColAction, LVIR_BOUNDS, &rc)) {
                if (pt.x < (rc.left + rc.right) / 2 && nm->code == NM_CLICK) {
                    if (cbs_.onEdit) cbs_.onEdit(rows_[p->iItem].ruleId);
                } else {
                    if (nm->code == NM_DBLCLK) {
                        if (cbs_.onEdit) cbs_.onEdit(rows_[p->iItem].ruleId);
                    } else {
                        if (cbs_.onDelete) cbs_.onDelete(rows_[p->iItem].ruleId);
                    }
                }
            }
        }
    }
}

}  // namespace aps::gui
