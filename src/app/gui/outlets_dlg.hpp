// Outlet list editor dialog: list + add/edit/remove. Simple by design.
#pragma once

#include <windows.h>

#include <vector>

#include "aps/config.hpp"

namespace aps::gui {

// Modal editor. `outlets` is edited in place; returns true when the user
// confirmed (false on cancel; edits are still applied to the vector either
// way so the caller decides whether to save).
bool showOutletsDialog(HWND parent, std::vector<Outlet>& outlets);

}  // namespace aps::gui
