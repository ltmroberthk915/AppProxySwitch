// Control-pipe name shared by the engine (server) and the GUI (client).
// Lives in appsw_common so both the engine and GUI-side tests can link it.
#include "aps/engine_main.hpp"

namespace aps {

std::wstring controlPipeName() {
    return L"\\\\.\\pipe\\AppProxySwitchCtrl";
}

}  // namespace aps
