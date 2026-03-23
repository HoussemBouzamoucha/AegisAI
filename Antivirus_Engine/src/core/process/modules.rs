// File: src/core/process_scanner/modules.rs
// Stage 3: Loaded DLL / module enumeration per process.
//
// TODO: Enumerate loaded modules using EnumProcessModules (psapi)
// For each module collect:
//   - Name and full path
//   - Base address and size
//   - Flag modules outside standard paths as suspicious
//   - Detect unsigned or tampered modules (pelite)
//
// Required Cargo.toml additions when implementing:
//   [target.'cfg(windows)'.dependencies]
//   windows = { version = "0.58", features = [
//     "Win32_System_ProcessStatus",
//     "Win32_System_Threading",
//   ]}
//   pelite = "0.10"

#[allow(dead_code)]
pub fn enumerate_modules(_pid: u32) -> Vec<super::types::ModuleInfo> {
    // Stage 3 — not implemented yet
    vec![]
}