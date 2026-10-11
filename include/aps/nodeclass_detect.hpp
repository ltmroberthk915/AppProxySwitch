// Node-class preference ("IEPL" / "家宽" / "原生" / "中转" / "直连" /
// "星链" / "进阶"): replaces the old hard-coded IEPL tie-break with an
// explicit, user-selectable filter. Matching is keyword-contains over the
// raw node name — deliberately tolerant so future providers with different
// naming survive: every class maps to a CN+EN keyword set, and a provider
// vocabulary the detector has never seen simply fails open (the class
// preference reorders, never hard-filters).
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace aps::nodeclass {

// wanted empty ("不限") matches everything; otherwise true when the node
// name contains any keyword of that class (case-insensitive).
bool matches(std::string_view nodeName, std::string_view wanted);
// Multi-select variant: empty set = 不限.
bool matchesAny(std::string_view nodeName, const std::vector<std::string>& wanted);

}  // namespace aps::nodeclass
