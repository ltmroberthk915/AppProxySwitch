// "Choose from running processes" dialog (snapshot + svchost warning).
#pragma once

#include <windows.h>

#include <optional>
#include <string>

namespace aps::gui {

// Returns the full path of the selected process executable, or nullopt.
std::optional<std::wstring> showPickProcessDialog(HWND parent);

}  // namespace aps::gui
