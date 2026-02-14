use antivirus_engine::core::file_system::scanner::FileSystemScanner;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// AegisAI Antivirus Engine - Command Line Interface
#[derive(Parser)]
#[command(name = "AegisAI Antivirus")]
#[command(author = "AegisAI Team")]
#[command(version = "1.0.0")]
#[command(about = "Advanced antivirus scanning engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a single file
    ScanFile {
        /// Path to the file to scan
        #[arg(short, long)]
        path: PathBuf,
        
        /// Output format (json or text)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    
    /// Scan a directory
    ScanDir {
        /// Path to the directory to scan
        #[arg(short, long)]
        path: PathBuf,
        
        /// Scan recursively
        #[arg(short, long, default_value = "true")]
        recursive: bool,
        
        /// Output format (json or text)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    
    /// Get version information
    Version,
}

#[derive(Serialize, Deserialize)]
struct JsonOutput {
    success: bool,
    results: Vec<ScanResultJson>,
    statistics: Statistics,
}

#[derive(Serialize, Deserialize)]
struct ScanResultJson {
    path: String,
    level: String,
    reason: String,
    hash: Option<String>,
    signature: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Statistics {
    total: usize,
    clean: usize,
    suspicious: usize,
    malicious: usize,
    errors: usize,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    let scanner = FileSystemScanner::new();
    
    match cli.command {
        Commands::ScanFile { path, format } => {
            if !path.exists() {
                eprintln!("Error: File not found: {}", path.display());
                std::process::exit(1);
            }
            
            let result = scanner.scan_file(&path)?;
            
            if format == "json" {
                let json_result = ScanResultJson {
                    path: result.path.display().to_string(),
                    level: format!("{:?}", result.level),
                    reason: result.reason.clone(),
                    hash: result.hash.clone(),
                    signature: result.signature.clone(),
                };
                
                let stats = Statistics {
                    total: 1,
                    clean: if matches!(result.level, antivirus_engine::core::types::ThreatLevel::Clean) { 1 } else { 0 },
                    suspicious: if matches!(result.level, antivirus_engine::core::types::ThreatLevel::Suspicious) { 1 } else { 0 },
                    malicious: if matches!(result.level, antivirus_engine::core::types::ThreatLevel::Malicious) { 1 } else { 0 },
                    errors: if matches!(result.level, antivirus_engine::core::types::ThreatLevel::Error) { 1 } else { 0 },
                };
                
                let output = JsonOutput {
                    success: true,
                    results: vec![json_result],
                    statistics: stats,
                };
                
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Scan Result:");
                println!("  Path: {}", result.path.display());
                println!("  Level: {:?}", result.level);
                println!("  Reason: {}", result.reason);
                if let Some(hash) = &result.hash {
                    println!("  Hash: {}", hash);
                }
                if let Some(sig) = &result.signature {
                    println!("  Signature: {}", sig);
                }
            }
        }
        
        Commands::ScanDir { path, recursive, format } => {
            if !path.exists() {
                eprintln!("Error: Directory not found: {}", path.display());
                std::process::exit(1);
            }
            
            let mut all_results = Vec::new();
            let mut stats = Statistics {
                total: 0,
                clean: 0,
                suspicious: 0,
                malicious: 0,
                errors: 0,
            };
            
            // Scan directory
            for result in scanner.scan_directory(&path, recursive) {
                match result {
                    Ok(scan_result) => {
                        stats.total += 1;
                        
                        match scan_result.level {
                            antivirus_engine::core::types::ThreatLevel::Clean => stats.clean += 1,
                            antivirus_engine::core::types::ThreatLevel::Suspicious => stats.suspicious += 1,
                            antivirus_engine::core::types::ThreatLevel::Malicious => stats.malicious += 1,
                            antivirus_engine::core::types::ThreatLevel::Error => stats.errors += 1,
                        }
                        
                        if format == "json" {
                            all_results.push(ScanResultJson {
                                path: scan_result.path.display().to_string(),
                                level: format!("{:?}", scan_result.level),
                                reason: scan_result.reason.clone(),
                                hash: scan_result.hash.clone(),
                                signature: scan_result.signature.clone(),
                            });
                        } else {
                            // Print each result as we go
                            println!("[{:?}] {}: {}", 
                                scan_result.level, 
                                scan_result.path.display(),
                                scan_result.reason
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error during scan: {}", e);
                        stats.errors += 1;
                    }
                }
            }
            
            if format == "json" {
                let output = JsonOutput {
                    success: true,
                    results: all_results,
                    statistics: stats,
                };
                
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("\n=== Scan Complete ===");
                println!("Total: {}", stats.total);
                println!("Clean: {}", stats.clean);
                println!("Suspicious: {}", stats.suspicious);
                println!("Malicious: {}", stats.malicious);
                println!("Errors: {}", stats.errors);
            }
        }
        
        Commands::Version => {
            println!("AegisAI Antivirus Engine v1.0.0");
            println!("Rust-based malware detection engine");
        }
    }
    
    Ok(())
}