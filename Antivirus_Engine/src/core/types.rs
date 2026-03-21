// File: src/core/types.rs
// Core types shared across all scanner modules.

use std::fmt;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// ─── Threat level ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Clean      => "Clean",
            ThreatLevel::Suspicious => "Suspicious",
            ThreatLevel::Malicious  => "Malicious",
        }
    }

    pub fn is_threat(&self) -> bool {
        !matches!(self, ThreatLevel::Clean)
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            ThreatLevel::Clean      => "✅",
            ThreatLevel::Suspicious => "⚠️",
            ThreatLevel::Malicious  => "🚨",
        }
    }

    /// Numeric order for comparison: Clean=0, Suspicious=1, Malicious=2
    pub fn order(&self) -> u8 {
        match self {
            ThreatLevel::Clean      => 0,
            ThreatLevel::Suspicious => 1,
            ThreatLevel::Malicious  => 2,
        }
    }
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── File category ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileCategory {
    Executable,
    Script,
    Document,
    Archive,
    MacroEnabled,
    Unknown,
}

impl FileCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileCategory::Executable   => "executable",
            FileCategory::Script       => "script",
            FileCategory::Document     => "document",
            FileCategory::Archive      => "archive",
            FileCategory::MacroEnabled => "macro_enabled",
            FileCategory::Unknown      => "unknown",
        }
    }

    pub fn from_path(path: &std::path::Path) -> Self {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        match ext.as_str() {
            "exe" | "dll" | "sys" | "drv" | "scr" | "ocx" | "cpl" | "com" | "pif"
                => FileCategory::Executable,
            "bat" | "cmd" | "ps1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh" | "sh"
                => FileCategory::Script,
            "txt" | "md" | "rst" | "log" | "csv" | "json" | "xml" | "html" | "htm"
            | "toml" | "yaml" | "yml" | "ini" | "cfg" | "pdf" | "doc" | "docx"
            | "xls" | "xlsx" | "ppt" | "pptx"
                => FileCategory::Document,
            "zip" | "rar" | "7z" | "cab" | "tar" | "gz" | "bz2" | "xz"
                => FileCategory::Archive,
            "xlsm" | "docm" | "pptm" | "xlam"
                => FileCategory::MacroEnabled,
            _ => FileCategory::Unknown,
        }
    }
}

// ─── Context flags ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextFlag {
    RansomNoteNearby,
    MultipleRansomNotes,
    RansomwareExtension,
    MassModificationDetected,
    EncryptedCopyDetected,
    YaraRansomwareCorrelated,
    YaraFilenameCorrelated,
    HighRansomwareExtensionRatio,
}

impl ContextFlag {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContextFlag::RansomNoteNearby             => "ransom_note_nearby",
            ContextFlag::MultipleRansomNotes          => "multiple_ransom_notes",
            ContextFlag::RansomwareExtension          => "ransomware_extension",
            ContextFlag::MassModificationDetected     => "mass_modification_detected",
            ContextFlag::EncryptedCopyDetected        => "encrypted_copy_detected",
            ContextFlag::YaraRansomwareCorrelated     => "yara_ransomware_correlated",
            ContextFlag::YaraFilenameCorrelated       => "yara_filename_correlated",
            ContextFlag::HighRansomwareExtensionRatio => "high_ransomware_extension_ratio",
        }
    }
}

// ─── Detection signal ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub source: String,
    pub description: String,
    pub score: i32,
}

impl DetectionSignal {
    pub fn new(source: impl Into<String>, description: impl Into<String>, score: i32) -> Self {
        Self {
            source: source.into(),
            description: description.into(),
            score,
        }
    }
}

// ─── ScanResult ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub level: ThreatLevel,
    pub reason: String,
    pub hash: Option<String>,
    pub signature: Option<String>,
    pub confidence_score: f32,
    pub detection_signals: Vec<DetectionSignal>,
    pub file_category: FileCategory,
    pub context_flags: Vec<ContextFlag>,
}

impl ScanResult {
    pub fn clean(path: PathBuf, hash: Option<String>) -> Self {
        let category = FileCategory::from_path(&path);
        Self {
            path,
            level: ThreatLevel::Clean,
            reason: "No threats detected (multi-layer scan)".to_string(),
            hash,
            signature: None,
            confidence_score: 1.0,
            detection_signals: vec![],
            file_category: category,
            context_flags: vec![],
        }
    }

    pub fn error(path: PathBuf, reason: String) -> Self {
        let category = FileCategory::from_path(&path);
        Self {
            path,
            level: ThreatLevel::Clean,
            reason,
            hash: None,
            signature: None,
            confidence_score: 0.0,
            detection_signals: vec![],
            file_category: category,
            context_flags: vec![],
        }
    }

    pub fn add_context_flag(&mut self, flag: ContextFlag) {
        if !self.context_flags.contains(&flag) {
            self.context_flags.push(flag);
        }
    }

    /// Escalate threat level due to directory context.
    /// Only escalates — never downgrades.
    pub fn escalate(&mut self, new_level: ThreatLevel, reason: String, confidence: f32) {
        // Fix: compare order() values — both are u8, no type mismatch
        if new_level.order() > self.level.order() {
            self.level = new_level;
            self.reason = format!("{} [context: {}]", self.reason, reason);
            self.confidence_score = self.confidence_score.max(confidence);
        }
    }

    pub fn from_parts(
        path: PathBuf,
        level: ThreatLevel,
        reason: String,
        hash: Option<String>,
        signature: Option<String>,
        confidence_score: f32,
        detection_signals: Vec<DetectionSignal>,
    ) -> Self {
        let category = FileCategory::from_path(&path);
        Self {
            path,
            level,
            reason,
            hash,
            signature,
            confidence_score,
            detection_signals,
            file_category: category,
            context_flags: vec![],
        }
    }
}