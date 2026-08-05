// File: src/core/file_system/yara_engine.rs
// YARA Rule Engine — loads .yar files from yara_rules/ and scans file content

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::fs;
use std::sync::Arc;
use anyhow::Result;

/// Per-scan YARA timeout.  YARA rules with complex regexes can spin for
/// minutes on certain file contents (e.g. highly repetitive PE sections that
/// trigger catastrophic backtracking).  5 s is generous for a real malware
/// signature — if a rule needs longer it's too slow for real-time scanning.
#[allow(dead_code)]
const YARA_SCAN_TIMEOUT: Duration = Duration::from_secs(5);

/// A single YARA match result
#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    #[allow(dead_code)]
    pub tags: Vec<String>,
    pub meta_description: Option<String>,
}

/// YARA scanning engine backed by yara-x
pub struct YaraEngine {
    /// Pre-compiled rules wrapped in Arc so worker threads can each create a
    /// `yara_x::Scanner` that borrows from the same compiled bytecode without
    /// copying rules — zero per-file JIT re-initialisation.
    rules: Option<Arc<yara_x::Rules>>,
    /// How many .yar files were loaded
    pub rules_loaded: usize,
}

impl YaraEngine {
    /// Create engine and load all .yar files from the given directory (recursive)
    pub fn load_from_directory(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.exists() {
            eprintln!("YARA rules directory not found: {}", rules_dir.display());
            return Ok(Self { rules: None, rules_loaded: 0 });
        }

        // Collect all .yar / .yara files
        let yar_files = Self::collect_rule_files(rules_dir);

        if yar_files.is_empty() {
            eprintln!("No .yar files found in {}", rules_dir.display());
            return Ok(Self { rules: None, rules_loaded: 0 });
        }

        // Compile all rules into a single compiler pass
        let mut compiler = yara_x::Compiler::new();
        let mut loaded = 0;

        for path in &yar_files {
            match fs::read_to_string(path) {
                Ok(source) => {
                    if let Err(e) = compiler.add_source(source.as_str()) {
                        // Log but don't abort — some community rules may have syntax issues
                        eprintln!("YARA compile warning ({}): {}", path.display(), e);
                    } else {
                        loaded += 1;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read YARA rule file {}: {}", path.display(), e);
                }
            }
        }

        let rules = if loaded > 0 {
            let r = compiler.build();
            eprintln!("YARA: successfully compiled {} rule files", loaded);
            Some(Arc::new(r))
        } else {
            None
        };

        Ok(Self { rules, rules_loaded: loaded })
    }

    /// Scan a file and return any matching YARA rules.
    ///
    /// If the caller has already read the file into memory (e.g. for
    /// heuristics), pass the buffer as `preloaded_bytes` to avoid a redundant
    /// disk read.  Pass `None` to let the engine read the file itself.
    ///
    /// A 5-second per-scan timeout is enforced — YARA rules with pathological
    /// regex patterns can otherwise spin for minutes on crafted file content.
    /// Timed-out scans return an empty match list (the file proceeds to the
    /// heuristic decision without a YARA verdict).
    pub fn scan_file(&self, path: &Path, preloaded_bytes: Option<&[u8]>) -> Result<Vec<YaraMatch>> {
        let rules = match &self.rules {
            Some(r) => r,
            None => return Ok(vec![]),
        };

        // Use the caller-supplied buffer when available; otherwise read.
        let owned: Vec<u8>;
        let data: &[u8] = match preloaded_bytes {
            Some(b) => b,
            None => {
                owned = match fs::read(path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("YARA: cannot read {}: {}", path.display(), e);
                        return Ok(vec![]);
                    }
                };
                &owned
            }
        };

        // NOTE: set_timeout() is intentionally disabled — it activates wasmtime
        // epoch interruption which races against the heartbeat thread and causes
        // non-unwindable aborts in multi-threaded scan workers.  File-size
        // filtering (YARA_MAX_FILE_BYTES in scanner.rs) is the primary guard
        // against long-running scans; each scan worker processes files serially.
        let mut scanner = yara_x::Scanner::new(rules);
        Self::collect_matches_from_scanner(&mut scanner, data)
    }

    /// Scan raw bytes directly (useful for memory scanning)
    #[allow(dead_code)]
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let rules = match &self.rules {
            Some(r) => r,
            None => return Ok(vec![]),
        };
        let mut scanner = yara_x::Scanner::new(rules);
        Self::collect_matches_from_scanner(&mut scanner, data)
    }

    /// Scan `data` using a **caller-provided Scanner**, avoiding a fresh
    /// `Scanner::new()` for every file.
    ///
    /// Workers in `parallel_scan` create one `yara_x::Scanner` at thread
    /// start and pass `&mut scanner` here on every file — the wasmtime JIT
    /// state is fully warm and reused across all files in that worker.
    pub fn scan_data_reusing(
        scanner: &mut yara_x::Scanner<'_>,
        data: &[u8],
    ) -> Result<Vec<YaraMatch>> {
        Self::collect_matches_from_scanner(scanner, data)
    }

    /// Clone the inner `Arc<Rules>` so worker threads can each create a
    /// `yara_x::Scanner<'_>` that borrows from the same compiled bytecode.
    /// Returns `None` when the engine has no compiled rules.
    pub fn rules_arc(&self) -> Option<Arc<yara_x::Rules>> {
        self.rules.clone()
    }

    // ── Shared match-collection helper ────────────────────────────────────────

    fn collect_matches_from_scanner(
        scanner: &mut yara_x::Scanner<'_>,
        data: &[u8],
    ) -> Result<Vec<YaraMatch>> {
        let results = match scanner.scan(data) {
            Ok(r)  => r,
            Err(e) => return Err(e.into()),
        };

        let matches = results
            .matching_rules()
            .map(|rule| {
                let tags: Vec<String> = rule.tags()
                    .map(|t| t.identifier().to_string())
                    .collect();
                let meta_description = rule
                    .metadata()
                    .find(|(key, _)| *key == "description")
                    .and_then(|(_, val)| {
                        if let yara_x::MetaValue::String(s) = val {
                            Some(s.to_string())
                        } else {
                            None
                        }
                    });
                YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    tags,
                    meta_description,
                }
            })
            .collect();

        Ok(matches)
    }

    /// Create a disabled engine with no rules
    pub fn disabled() -> Self {
        Self { rules: None, rules_loaded: 0 }
    }

    /// Whether the engine has compiled rules ready
    pub fn is_ready(&self) -> bool {
        self.rules.is_some()
    }

    /// Collect all .yar and .yara files recursively
    fn collect_rule_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();

        let read_dir = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return files,
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip .git and deprecated folders
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                if name != ".git" && name != "deprecated" {
                    files.extend(Self::collect_rule_files(&path));
                }
            } else if let Some(ext) = path.extension() {
                let ext_str = ext.to_str().unwrap_or("").to_lowercase();
                if ext_str == "yar" || ext_str == "yara" {
                    // Skip index files — they use `include` directives that
                    // don't resolve when loading files individually
                    let name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    if !name.contains("index") {
                        files.push(path);
                    }
                }
            }
        }

        files
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        // Try to find yara_rules relative to the binary
        let candidates = [
            PathBuf::from("yara_rules"),
            PathBuf::from("../yara_rules"),
            PathBuf::from("../../yara_rules"),
        ];

        for path in &candidates {
            if path.exists() {
                return Self::load_from_directory(path)
                    .unwrap_or(Self { rules: None, rules_loaded: 0 });
            }
        }

        eprintln!("YARA: no rules directory found, engine disabled");
        Self { rules: None, rules_loaded: 0 }
    }
}