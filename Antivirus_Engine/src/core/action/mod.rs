// File: src/core/action/mod.rs
//
// Post-verdict containment actions.
//
// All public types and functions live in `executor`.  This module re-exports
// the subset that the daemon loop (`main.rs`) needs so callers write
// `core::action::quarantine_file(...)` instead of the full path.

pub mod executor;

// Re-export the action functions used by the daemon loop in main.rs.
// Result structs (QuarantineResult, BlockIpResult, …) are pub in executor.rs
// and can be imported directly from there when a caller needs to name the type.
pub use executor::{
    quarantine_file,
    block_ip,
    remove_block_ip,
    dump_memory,
    check_persistence,
    isolate_network,
    restore_network,
};
