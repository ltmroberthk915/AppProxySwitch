// Engine process entry (--engine mode) shared between builds.
#pragma once

#include <string>

namespace aps {

// The control pipe name.
std::wstring controlPipeName();

// Runs the headless engine using `configPath` (empty = default location).
// Blocks until a STOP message arrives or the process is terminated.
// Returns the process exit code.
int runEngineMode(const std::wstring& configPath);

}  // namespace aps
