// File: src/core/process_scanner/mod.rs
// Advanced Process Scanner — replaces core/process/
//
// Stage 1 (current): Core process listing + heuristic scoring + JSON output
// Stage 2 (future):  Handles enumeration (Win32 NtQuerySystemInformation)
// Stage 3 (future):  Loaded modules / DLLs (EnumProcessModules)
// Stage 4 (future):  Services / drivers (SCM API)
// Stage 5 (future):  Anomaly / anti-forensics checks

pub mod types;
pub mod heuristics;
pub mod scanner;
pub mod output;
pub mod handles;
pub mod modules;
pub mod services;

pub use scanner::ProcessScanner;
pub use output::OutputFormat;
pub use types::{ProcessInfo, ScanStatistics, ThreatLevel};