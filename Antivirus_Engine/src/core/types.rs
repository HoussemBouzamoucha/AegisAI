use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub level: ThreatLevel,
    pub reason: String,
    pub hash: Option<String>,
    pub signature: Option<String>,
}

impl ScanResult {
    pub fn clean(path: PathBuf) -> Self {
        ScanResult {
            path,
            level: ThreatLevel::Clean,
            reason: String::new(),
            hash: None,
            signature: None,
        }
    }

    pub fn suspicious(path: PathBuf, reason: String) -> Self {
        ScanResult {
            path,
            level: ThreatLevel::Suspicious,
            reason,
            hash: None,
            signature: None,
        }
    }

    pub fn malicious(path: PathBuf, reason: String, signature: Option<String>) -> Self {
        ScanResult {
            path,
            level: ThreatLevel::Malicious,
            reason,
            hash: None,
            signature,
        }
    }

    pub fn error(path: PathBuf, reason: String) -> Self {
        ScanResult {
            path,
            level: ThreatLevel::Error,
            reason,
            hash: None,
            signature: None,
        }
    }
}