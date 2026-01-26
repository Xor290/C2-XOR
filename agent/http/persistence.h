#pragma once
#include <string>

// ============================================================================
// MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder Persistence
// https://attack.mitre.org/techniques/T1547/001/
//
// Auto-persistence module - installs persistence automatically on first run
// ============================================================================

bool is_persistence_installed();

bool install_persistence();

std::string get_persistence_status();
