// File: src/core/process_scanner/handles.rs
// Stage 2: Handle enumeration per process.
//
// TODO: Enumerate handles using NtQuerySystemInformation (SystemHandleInformation)
// Handle types to enumerate:
//   - File handles
//   - Mutex / semaphore handles
//   - Port handles
//   - Event handles
//   - Registry key handles
//
// Required Cargo.toml additions when implementing:
//   [target.'cfg(windows)'.dependencies]
//   windows = { version = "0.58", features = [
//     "Win32_System_Threading",
//     "Win32_Foundation",
//     "Win32_System_WindowsProgramming",
//   ]}

#[allow(dead_code)]
pub fn enumerate_handles(_pid: u32) -> Vec<super::types::HandleInfo> {
    // Stage 2 — not implemented yet
    vec![]
}