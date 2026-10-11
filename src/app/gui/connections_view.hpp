// "活动连接" ListView: read-only snapshot of the engine's per-second
// `connections` array (NAT active flows with process/destination/outlet/
// bytes/duration/host). Pure display — no interactions, no callbacks.
#pragma once

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <vector>

namespace aps::gui {

class ConnectionsView {
public:
    struct ConnRow {
        std::wstring key;         // stable flow identity across sorted snapshots
        std::wstring proc;        // process path (display: basename)
        std::wstring target;      // "ip:port"
        std::wstring ruleName;    // rule name or id
        std::wstring outletName;  // outlet name, "默认出口", or kernel id
        std::wstring state;       // "SYN" | "已建立" | "关闭中"
        std::wstring host;        // reverse-DNS name or "-"
        uint64_t bytesUp = 0;
        uint64_t bytesDown = 0;
        int64_t durationMs = 0;
    };

    bool create(HWND parent, HINSTANCE inst, int x, int y, int w, int h);
    HWND hwnd() const { return hwnd_; }

    // Full repopulate (the engine pushes a complete snapshot each second).
    void setConnections(const std::vector<ConnRow>& rows);

    // ListView notifications from the owner's WM_NOTIFY (idFrom == control
    // id). Nothing is interactive; present for symmetry with RulesView.
    void handleNotify(LPNMHDR nm);

private:
    std::wstring humanBytes(uint64_t n) const;
    std::wstring humanDuration(int64_t ms) const;

    bool building_ = false;
    HWND hwnd_ = nullptr;
    std::vector<ConnRow> rows_;
};

}  // namespace aps::gui
