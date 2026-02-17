// Process monitoring and analysis module

pub mod scanner;
pub mod heuristics;

pub use scanner::ProcessScanner;
pub use heuristics::ProcessAnalyzer;