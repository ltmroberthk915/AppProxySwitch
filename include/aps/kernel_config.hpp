#pragma once
#include <cstdint>
#include <string>

namespace aps {
struct KernelLaunchConfig {
    std::string configDir;
    std::string configFile;
    std::string pipe;
    std::string secret;
    uint16_t mixedPort = 0;
    uint16_t socksPort = 0;
};
// Windows quoting and Go flag syntax (-flag value, -flag=value, --flag).
// Only top-level scalar YAML fields are consumed; no subscriptions/nodes.
KernelLaunchConfig parseKernelLaunchConfig(const std::string& cmdline,
                                            const std::string& yaml = {});
KernelLaunchConfig readKernelLaunchConfig(const std::string& cmdline);
}
