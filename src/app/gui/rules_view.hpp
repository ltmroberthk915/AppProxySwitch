// Rules ListView: checkbox, icon, name, path, PID, connections, traffic,
// last error, and an action column (编辑 / 删除) that reacts to clicks.
#pragma once

#include <windows.h>
#include <commctrl.h>

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "aps/config.hpp"

namespace aps::gui {

class RulesView {
public:
    struct RuleRow {
        std::string ruleId;
        bool enabled = false;
        std::wstring path;
        std::wstring name;
        // live data (from STATS messages)
        uint32_t lastPid = 0;
        uint64_t conns = 0;
        uint64_t blocked = 0;
        uint64_t bytesUp = 0, bytesDown = 0;
        std::wstring lastError;
    };

    struct Callbacks {
        std::function<void(const std::string& ruleId, bool enabled)> onToggle;
        std::function<void(const std::string& ruleId)> onEdit;
        std::function<void(const std::string& ruleId)> onDelete;
    };

    bool create(HWND parent, HINSTANCE inst, int x, int y, int w, int h);
    HWND hwnd() const { return hwnd_; }
    void setCallbacks(Callbacks cbs) { cbs_ = std::move(cbs); }

    void setRules(const std::vector<RuleRow>& rows);
    void updateLiveData(const std::string& ruleId, uint32_t pid, uint64_t conns,
                        uint64_t blocked, uint64_t up, uint64_t down,
                        const std::wstring& lastError);

    void handleNotify(LPNMHDR nm);

private:
    int rowOf(const std::string& ruleId) const;
    void refreshRow(int i);
    std::wstring humanBytes(uint64_t n) const;

    // True while the list is being (re)populated programmatically. Windows
    // ListView fires LVN_ITEMCHANGED for every InsertItem/SetCheckState —
    // those must NEVER be treated as user clicks, otherwise opening the GUI
    // would silently disable every rule (a bug that bit us: new rows start
    // UNCHECKED, which looked exactly like the user unchecking them).
    bool building_ = false;

    HWND hwnd_ = nullptr;
    HWND headerTooltipOwner_ = nullptr;
    HIMAGELIST icons_ = nullptr;
    std::vector<RuleRow> rows_;
    std::map<std::wstring, int> iconCache_;
    Callbacks cbs_;
};

}  // namespace aps::gui
