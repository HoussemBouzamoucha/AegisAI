// File: src/core/process_scanner/services.rs
// Stage 4: Service and driver enumeration per process.
//
// TODO: Enumerate services using Service Control Manager (SCM) API
// For each service collect:
//   - Name and display name
//   - Service type (kernel driver / filesystem driver / own process / shared process)
//   - Current status (running / stopped / paused)
//   - Associate with hosting process PID
//
// Required Cargo.toml additions when implementing:
//   [target.'cfg(windows)'.dependencies]
//   windows = { version = "0.58", features = [
//     "Win32_System_Services",
//     "Win32_Foundation",
//   ]}

#[allow(dead_code)]
pub fn enumerate_services(_pid: u32) -> Vec<super::types::ServiceInfo> {
    // Stage 4 — not implemented yet
    vec![]
}