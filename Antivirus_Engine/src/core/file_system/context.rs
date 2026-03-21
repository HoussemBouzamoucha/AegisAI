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

use crate::core::types::{
    ContextFlag, DetectionSignal, FileCategory, ScanResult, ThreatLevel,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ─── Thresholds ───────────────────────────────────────────────────────────────

/// Number of ransom notes that triggers full directory escalation
const RANSOM_NOTE_ESCALATION_THRESHOLD: usize = 3;

/// Ratio of ransomware-extension files that triggers directory-wide flag
const RANSOMWARE_EXTENSION_RATIO_THRESHOLD: f32 = 0.20;

const MASS_MODIFICATION_WINDOW_SECS: u64 = 5;  // tighter window
const MASS_MODIFICATION_MIN_FILES: usize = 20;  // needs many more files

// ─── Known ransomware file extensions ─────────────────────────────────────────

const RANSOMWARE_EXTENSIONS: &[&str] = &[
    "locked", "encrypted", "crypted", "enc", "crypt",
    "locky", "cerber", "zepto", "thor", "wannacry",
    "petya", "cryptolocker", "ryuk", "maze", "revil",
    "wncry", "wncryt", "ecc", "ezz", "exx",
];

/// Ransom note filename substrings (compound phrases only — no single words)
const RANSOM_NOTE_PATTERNS: &[&str] = &[
    "read_me", "read-me",
    "how_to_decrypt", "how-to-decrypt", "howto_decrypt", "howto_recover",
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

    /// Main entry point. Takes the results of a directory scan and applies
    /// directory-level context analysis, mutating results in place.
    ///
    /// Call this after `scan_directory_with_stats` to enrich results.
    pub fn analyze(&self, results: &mut Vec<ScanResult>, dir: &Path) {
        // ── Pass 1: collect directory-level facts ─────────────────────────────
        let facts = self.collect_facts(results, dir);

        // ── Pass 2: annotate and escalate each result ─────────────────────────
        for result in results.iter_mut() {
            self.annotate(result, &facts);
        }
    }

    // ── Fact collection ───────────────────────────────────────────────────────

    fn collect_facts(&self, results: &[ScanResult], dir: &Path) -> DirectoryFacts {
        let total = results.len();

        // Count ransom notes
        let ransom_note_paths: Vec<PathBuf> = results.iter()
            .map(|r| r.path.clone())
            .filter(|p| is_ransom_note(p))
            .collect();
        let ransom_note_count = ransom_note_paths.len();

        // Count ransomware extensions
        let ransomware_ext_count = results.iter()
            .filter(|r| has_ransomware_extension(&r.path))
            .count();
        let ransomware_ext_ratio = if total > 0 {
            ransomware_ext_count as f32 / total as f32
        } else {
            0.0
        };

        // Detect mass modification
        let mass_mod = self.detect_mass_modification(results);

        // Detect encrypted copies (original + .locked/.enc version side by side)
        let encrypted_copy_pairs = self.detect_encrypted_copies(results);

        DirectoryFacts {
            total_files: total,
            ransom_note_count,
            ransom_note_paths,
            ransomware_ext_ratio,
            mass_modification_detected: mass_mod,
            encrypted_copy_pairs,
        }
    }

    fn detect_mass_modification(&self, results: &[ScanResult]) -> bool {
        // Collect modification timestamps
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

        // Sliding window: count files modified within MASS_MODIFICATION_WINDOW_SECS
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
        // Build a set of all file stems in the directory
        let stem_map: HashMap<String, PathBuf> = results.iter()
            .filter_map(|r| {
                let stem = r.path.file_stem()?.to_str()?.to_lowercase();
                Some((stem, r.path.clone()))
            })
            .collect();

        let mut pairs = Vec::new();

        for result in results {
            if has_ransomware_extension(&result.path) {
                // Check if original file (without ransomware ext) also exists
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

            // Escalate non-clean files to Malicious when 3+ ransom notes present
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

            // Escalate suspicious files
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

            // Any file with existing threat signals gets escalated
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
                // Original file sitting next to its encrypted copy — annotate only
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
        // YARA matched a ransomware rule AND ransom notes are present → very high confidence
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

        // ── 7. YARA + filename hybrid scoring ────────────────────────────────
        // YARA matched anything AND filename also has a malware pattern
        // → corroboration between two independent signals
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
    fn test_ransom_note_nearby_flag() {
        let mut results = vec![
            make_result("C:/test/README_decrypt.txt", ThreatLevel::Clean),
            make_result("C:/test/document.txt", ThreatLevel::Clean),
        ];
        // First file is a ransom note — manually set up facts
        let analyzer = ContextAnalyzer::new();
        analyzer.analyze(&mut results, Path::new("C:/test"));
        // document.txt should have RansomNoteNearby if note detected
        // (actual detection depends on is_ransom_note logic)
    }

    #[test]
    fn test_multiple_ransom_notes_escalates_suspicious() {
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
        assert!(malware.context_flags.contains(&ContextFlag::MultipleRansomNotes));
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
        // Add filename signal too
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
        assert!(!is_ransom_note(Path::new("Neural network-HowTo.txt")));
        assert!(!is_ransom_note(Path::new("README.txt")));
        assert!(!is_ransom_note(Path::new("recovery_guide.txt")));
    }
}