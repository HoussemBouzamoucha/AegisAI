// File: src/core/file_system/context.rs
// Directory-Level Context Analysis Engine
//
// Performs a second pass over scan results after individual file scanning
// to detect patterns that are only visible at directory scope:
//
//   1. Ransom note counting        — 1 note = flag, 3+ notes = escalate all
//   2. Mass modification           — many files modified within same time window
//   3. Ransomware extension ratio  — >20% of files have ransomware extensions
//   4. Encrypted copy detection    — original + .locked/.enc copy side by side
//   5. YARA + filename correlation — YARA ransomware hit AND ransom note nearby
//   6. YARA + filename hybrid      — YARA match corroborated by filename pattern
//
// IMPORTANT: analyze() operates on a group of files from the SAME directory.
// Cross-directory isolation is handled by scanner.rs which groups results
// by parent directory before calling analyze() — preventing ransom notes
// in one subdirectory from escalating files in sibling directories.

use crate::core::types::{
    ContextFlag, DetectionSignal, ScanResult, ThreatLevel,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ─── Thresholds ───────────────────────────────────────────────────────────────

/// Number of ransom notes that triggers full directory escalation
const RANSOM_NOTE_ESCALATION_THRESHOLD: usize = 3;

/// Ratio of ransomware-extension files that triggers directory-wide flag
const RANSOMWARE_EXTENSION_RATIO_THRESHOLD: f32 = 0.20;

/// Time window (seconds) for mass-modification detection.
/// Real ransomware encrypts hundreds of files per second.
/// Set high enough to not trigger on normal file creation by scripts.
const MASS_MODIFICATION_WINDOW_SECS: u64 = 5;

/// Minimum files modified in window to count as mass modification.
/// Raised from 5 to 20 — avoids triggering on test file creation.
const MASS_MODIFICATION_MIN_FILES: usize = 20;

// ─── Known ransomware file extensions ─────────────────────────────────────────

const RANSOMWARE_EXTENSIONS: &[&str] = &[
    "locked", "encrypted", "crypted", "enc", "crypt",
    "locky", "cerber", "zepto", "thor", "wannacry",
    "petya", "cryptolocker", "ryuk", "maze", "revil",
    "wncry", "wncryt", "ecc", "ezz", "exx",
];

/// Ransom note filename substrings — compound phrases only.
/// Single words like "decrypt", "recovery", "readme" excluded
/// to prevent false positives on legitimate files.
const RANSOM_NOTE_PATTERNS: &[&str] = &[
    "read_me", "read-me",
    "how_to_decrypt", "how-to-decrypt",
    "howto_decrypt", "howto_recover",
    "decrypt_instructions", "decrypt_files",
    "recovery_instructions", "ransom_note",
    "your_files_encrypted", "files_encrypted",
    "!!!",
];

fn is_ransom_note(path: &Path) -> bool {
    let name = path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_lowercase())
        .unwrap_or_default();

    let ext = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if !["txt", "html", "htm", "hta"].contains(&ext.as_str()) {
        return false;
    }

    RANSOM_NOTE_PATTERNS.iter().any(|p| name.contains(p))
}

fn has_ransomware_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| RANSOMWARE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn has_yara_ransomware_signal(result: &ScanResult) -> bool {
    result.detection_signals.iter().any(|s| {
        s.source == "yara" && (
            s.description.to_lowercase().contains("ransom")
                || s.description.to_lowercase().contains("wanna")
                || s.description.to_lowercase().contains("crypt")
                || s.description.to_lowercase().contains("locker")
        )
    })
}

fn has_yara_signal(result: &ScanResult) -> bool {
    result.detection_signals.iter().any(|s| s.source == "yara")
}

fn has_filename_signal(result: &ScanResult) -> bool {
    result.detection_signals.iter().any(|s| s.source == "filename")
}

// ─── Context Analyzer ─────────────────────────────────────────────────────────

pub struct ContextAnalyzer;

impl ContextAnalyzer {
    pub fn new() -> Self { Self }

    /// Analyze a group of files from the SAME directory.
    ///
    /// This must only be called with files sharing the same parent directory.
    /// scanner.rs groups results by parent dir before calling this — ensuring
    /// ransom notes in one subdirectory do not escalate files in siblings.
    pub fn analyze(&self, results: &mut Vec<ScanResult>, dir: &Path) {
        // Pass 1: collect directory-level facts
        let facts = self.collect_facts(results, dir);

        // Pass 2: annotate and escalate each result
        for result in results.iter_mut() {
            self.annotate(result, &facts);
        }
    }

    // ── Fact collection ───────────────────────────────────────────────────────

    fn collect_facts(&self, results: &[ScanResult], _dir: &Path) -> DirectoryFacts {
        let total = results.len();

        // Count ransom notes in this directory only
        let ransom_note_paths: Vec<PathBuf> = results.iter()
            .map(|r| r.path.clone())
            .filter(|p| is_ransom_note(p))
            .collect();
        let ransom_note_count = ransom_note_paths.len();

        // Count ransomware extensions in this directory only
        let ransomware_ext_count = results.iter()
            .filter(|r| has_ransomware_extension(&r.path))
            .count();

        let ransomware_ext_ratio = if total > 0 {
            ransomware_ext_count as f32 / total as f32
        } else {
            0.0
        };

        let mass_modification_detected = self.detect_mass_modification(results);
        let encrypted_copy_pairs = self.detect_encrypted_copies(results);

        DirectoryFacts {
            total_files: total,
            ransom_note_count,
            ransom_note_paths,
            ransomware_ext_ratio,
            mass_modification_detected,
            encrypted_copy_pairs,
        }
    }

    fn detect_mass_modification(&self, results: &[ScanResult]) -> bool {
        let mut timestamps: Vec<u64> = results.iter()
            .filter_map(|r| {
                std::fs::metadata(&r.path).ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
            })
            .collect();

        if timestamps.len() < MASS_MODIFICATION_MIN_FILES {
            return false;
        }

        timestamps.sort_unstable();

        // Sliding window
        let mut max_in_window = 0usize;
        let mut left = 0;
        for right in 0..timestamps.len() {
            while timestamps[right] - timestamps[left] > MASS_MODIFICATION_WINDOW_SECS {
                left += 1;
            }
            max_in_window = max_in_window.max(right - left + 1);
        }

        max_in_window >= MASS_MODIFICATION_MIN_FILES
    }

    fn detect_encrypted_copies(&self, results: &[ScanResult]) -> Vec<(PathBuf, PathBuf)> {
        let stem_map: HashMap<String, PathBuf> = results.iter()
            .filter_map(|r| {
                let stem = r.path.file_stem()?.to_str()?.to_lowercase();
                Some((stem, r.path.clone()))
            })
            .collect();

        let mut pairs = Vec::new();

        for result in results {
            if has_ransomware_extension(&result.path) {
                if let Some(stem) = result.path.file_stem().and_then(|s| s.to_str()) {
                    let original_stem = stem.to_lowercase();
                    if stem_map.contains_key(&original_stem) {
                        let original = stem_map[&original_stem].clone();
                        pairs.push((original, result.path.clone()));
                    }
                }
            }
        }

        pairs
    }

    // ── Annotation pass ───────────────────────────────────────────────────────

    fn annotate(&self, result: &mut ScanResult, facts: &DirectoryFacts) {
        // ── 1. Ransom note flags ──────────────────────────────────────────────
        if facts.ransom_note_count >= 1 {
            result.add_context_flag(ContextFlag::RansomNoteNearby);
        }

        if facts.ransom_note_count >= RANSOM_NOTE_ESCALATION_THRESHOLD {
            result.add_context_flag(ContextFlag::MultipleRansomNotes);

            // Only escalate files that already have a threat signal
            // Clean files stay Clean — they are annotated only
            if result.level == ThreatLevel::Suspicious {
                result.escalate(
                    ThreatLevel::Malicious,
                    format!("{} ransom notes found in directory", facts.ransom_note_count),
                    0.80,
                );
                result.detection_signals.push(DetectionSignal::new(
                    "context",
                    format!("{} ransom notes in directory — escalated to Malicious",
                        facts.ransom_note_count),
                    5,
                ));
            }
        }

        // ── 2. Ransomware extension flag ──────────────────────────────────────
        if has_ransomware_extension(&result.path) {
            result.add_context_flag(ContextFlag::RansomwareExtension);
        }

        // ── 3. High ransomware extension ratio ────────────────────────────────
        if facts.ransomware_ext_ratio >= RANSOMWARE_EXTENSION_RATIO_THRESHOLD
            && facts.total_files >= 5
        {
            result.add_context_flag(ContextFlag::HighRansomwareExtensionRatio);

            if result.level == ThreatLevel::Suspicious {
                result.escalate(
                    ThreatLevel::Malicious,
                    format!("{:.0}% of files have ransomware extensions",
                        facts.ransomware_ext_ratio * 100.0),
                    0.85,
                );
                result.detection_signals.push(DetectionSignal::new(
                    "context",
                    format!("{:.0}% ransomware extension ratio in directory",
                        facts.ransomware_ext_ratio * 100.0),
                    5,
                ));
            }
        }

        // ── 4. Mass modification ──────────────────────────────────────────────
        if facts.mass_modification_detected {
            result.add_context_flag(ContextFlag::MassModificationDetected);

            if result.level == ThreatLevel::Suspicious {
                result.escalate(
                    ThreatLevel::Malicious,
                    "mass file modification detected in directory".to_string(),
                    0.80,
                );
                result.detection_signals.push(DetectionSignal::new(
                    "context",
                    "mass file modification pattern — ransomware activity indicator",
                    4,
                ));
            }
        }

        // ── 5. Encrypted copy detection ───────────────────────────────────────
        let is_in_pair = facts.encrypted_copy_pairs.iter()
            .any(|(orig, enc)| orig == &result.path || enc == &result.path);

        if is_in_pair {
            result.add_context_flag(ContextFlag::EncryptedCopyDetected);
            if result.level == ThreatLevel::Clean {
                // Annotate only — clean files are not escalated
                result.detection_signals.push(DetectionSignal::new(
                    "context",
                    "encrypted copy of this file exists in same directory",
                    0,
                ));
            } else {
                result.escalate(
                    ThreatLevel::Malicious,
                    "encrypted copy detected alongside original".to_string(),
                    0.85,
                );
            }
        }

        // ── 6. YARA + ransom note correlation ─────────────────────────────────
        if has_yara_ransomware_signal(result) && facts.ransom_note_count >= 1 {
            result.add_context_flag(ContextFlag::YaraRansomwareCorrelated);
            result.confidence_score = result.confidence_score.max(0.95);
            result.escalate(
                ThreatLevel::Malicious,
                "YARA ransomware signature corroborated by ransom note in directory".to_string(),
                0.95,
            );
            result.detection_signals.push(DetectionSignal::new(
                "context",
                "YARA ransomware rule + ransom note in same directory",
                5,
            ));
        }

        // ── 7. YARA + filename hybrid scoring ─────────────────────────────────
        if has_yara_signal(result) && has_filename_signal(result) {
            result.add_context_flag(ContextFlag::YaraFilenameCorrelated);
            result.confidence_score = result.confidence_score.max(0.90);

            if result.level == ThreatLevel::Suspicious {
                result.escalate(
                    ThreatLevel::Malicious,
                    "YARA match corroborated by malicious filename pattern".to_string(),
                    0.90,
                );
                result.detection_signals.push(DetectionSignal::new(
                    "context",
                    "YARA match + filename pattern — two independent signals",
                    3,
                ));
            }
        }
    }
}

impl Default for ContextAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Internal fact bundle ─────────────────────────────────────────────────────

struct DirectoryFacts {
    total_files: usize,
    ransom_note_count: usize,
    #[allow(dead_code)]
    ransom_note_paths: Vec<PathBuf>,
    ransomware_ext_ratio: f32,
    mass_modification_detected: bool,
    encrypted_copy_pairs: Vec<(PathBuf, PathBuf)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{DetectionSignal, FileCategory};

    fn make_result(path: &str, level: ThreatLevel) -> ScanResult {
        ScanResult {
            path: PathBuf::from(path),
            level,
            reason: "test".to_string(),
            hash: None,
            signature: None,
            confidence_score: 0.6,
            detection_signals: vec![],
            file_category: FileCategory::Document,
            context_flags: vec![],
        }
    }

    fn make_result_with_signal(path: &str, level: ThreatLevel, source: &str, desc: &str) -> ScanResult {
        let mut r = make_result(path, level);
        r.detection_signals.push(DetectionSignal::new(source, desc, 5));
        r
    }

    #[test]
    fn test_clean_files_not_escalated_by_ransom_notes() {
        // Clean files near ransom notes should be annotated but NOT escalated
        let mut results = vec![
            make_result("C:/test/how_to_decrypt.txt", ThreatLevel::Clean),
            make_result("C:/test/ransom_note.txt", ThreatLevel::Clean),
            make_result("C:/test/files_encrypted.txt", ThreatLevel::Clean),
            make_result("C:/test/document.txt", ThreatLevel::Clean),
        ];
        let analyzer = ContextAnalyzer::new();
        analyzer.analyze(&mut results, Path::new("C:/test"));

        let doc = results.iter().find(|r| r.path.ends_with("document.txt")).unwrap();
        assert_eq!(doc.level, ThreatLevel::Clean,
            "Clean file should not be escalated by ransom notes");
        assert!(doc.context_flags.contains(&ContextFlag::RansomNoteNearby),
            "Clean file should be annotated with RansomNoteNearby");
    }

    #[test]
    fn test_suspicious_escalated_by_multiple_ransom_notes() {
        let mut results = vec![
            make_result("C:/test/how_to_decrypt.txt", ThreatLevel::Clean),
            make_result("C:/test/ransom_note.txt", ThreatLevel::Clean),
            make_result("C:/test/files_encrypted.txt", ThreatLevel::Clean),
            make_result_with_signal("C:/test/malware.exe",
                ThreatLevel::Suspicious, "yara", "ransomware rule"),
        ];
        let analyzer = ContextAnalyzer::new();
        analyzer.analyze(&mut results, Path::new("C:/test"));

        let malware = results.iter().find(|r| r.path.ends_with("malware.exe")).unwrap();
        assert_eq!(malware.level, ThreatLevel::Malicious,
            "Suspicious file should be escalated by 3+ ransom notes");
        assert!(malware.context_flags.contains(&ContextFlag::MultipleRansomNotes));
    }

    #[test]
    fn test_sibling_dirs_isolated() {
        // Files in different directories must not affect each other
        // SuspiciousOnly files analyzed separately from RansomDir files
        let mut ransom_dir_results = vec![
            make_result("C:/test/RansomDir/how_to_decrypt.txt", ThreatLevel::Clean),
            make_result("C:/test/RansomDir/ransom_note.txt", ThreatLevel::Clean),
            make_result("C:/test/RansomDir/files_encrypted.txt", ThreatLevel::Clean),
        ];

        let mut suspicious_dir_results = vec![
            make_result_with_signal("C:/test/SuspiciousOnly/deploy.ps1",
                ThreatLevel::Suspicious, "keyword", "downloadstring"),
        ];

        let analyzer = ContextAnalyzer::new();
        analyzer.analyze(&mut ransom_dir_results, Path::new("C:/test/RansomDir"));
        analyzer.analyze(&mut suspicious_dir_results, Path::new("C:/test/SuspiciousOnly"));

        // deploy.ps1 should stay Suspicious — no ransom notes in its directory
        let deploy = &suspicious_dir_results[0];
        assert_eq!(deploy.level, ThreatLevel::Suspicious,
            "File in SuspiciousOnly should not be escalated by RansomDir notes");
    }

    #[test]
    fn test_yara_filename_correlated() {
        let mut results = vec![
            make_result_with_signal(
                "C:/test/keylogger.exe",
                ThreatLevel::Suspicious,
                "yara",
                "Keylogger_Generic rule matched",
            ),
        ];
        results[0].detection_signals.push(DetectionSignal::new(
            "filename", "Malware pattern: keylogger", 5
        ));
        let analyzer = ContextAnalyzer::new();
        analyzer.analyze(&mut results, Path::new("C:/test"));
        assert!(results[0].context_flags.contains(&ContextFlag::YaraFilenameCorrelated));
        assert_eq!(results[0].level, ThreatLevel::Malicious);
    }

    #[test]
    fn test_ransomware_extension_ratio() {
        let mut results: Vec<ScanResult> = (0..10).map(|i| {
            if i < 3 {
                make_result(&format!("C:/test/file{}.locked", i), ThreatLevel::Suspicious)
            } else {
                make_result(&format!("C:/test/file{}.txt", i), ThreatLevel::Clean)
            }
        }).collect();
        let analyzer = ContextAnalyzer::new();
        analyzer.analyze(&mut results, Path::new("C:/test"));
        let flagged = results.iter().any(|r|
            r.context_flags.contains(&ContextFlag::HighRansomwareExtensionRatio));
        assert!(flagged, "30% ransomware extension ratio should trigger flag");
    }

    #[test]
    fn test_is_ransom_note() {
        assert!(is_ransom_note(Path::new("how_to_decrypt.txt")));
        assert!(is_ransom_note(Path::new("files_encrypted.html")));
        assert!(is_ransom_note(Path::new("ransom_note.txt")));
        assert!(!is_ransom_note(Path::new("Neural network-HowTo.txt")));
        assert!(!is_ransom_note(Path::new("README.txt")));
        assert!(!is_ransom_note(Path::new("recovery_guide.txt")));
        assert!(!is_ransom_note(Path::new("howto_setup.txt")));
    }

    #[test]
    fn test_mass_modification_not_triggered_by_few_files() {
        // 7 files created at the same time should NOT trigger mass modification
        // (threshold is now 20 files)
        let results: Vec<ScanResult> = (0..7)
            .map(|i| make_result(&format!("C:/test/file{}.txt", i), ThreatLevel::Clean))
            .collect();
        let analyzer = ContextAnalyzer::new();
        let facts = analyzer.collect_facts(&results, Path::new("C:/test"));
        assert!(!facts.mass_modification_detected,
            "7 files should not trigger mass modification (threshold is 20)");
    }
}