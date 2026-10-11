// Add/edit rule dialog (built programmatically, modal).
#pragma once

#include <windows.h>

#include <optional>
#include <string>
#include <vector>

#include "aps/config.hpp"

namespace aps::gui {

// Returns the edited rule (id preserved when editing) or nullopt on cancel.
// `outlets` feeds the egress combo box ("" = default outlet).
std::optional<Rule> showRuleEditDialog(HWND parent, const Rule* edit,
                                       const std::vector<Outlet>* outlets = nullptr);

}  // namespace aps::gui
