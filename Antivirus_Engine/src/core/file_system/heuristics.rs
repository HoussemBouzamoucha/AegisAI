use crate::core::types::ScanResult;
use crate::core::utils::{calculate_entropy, is_pe_file};
use std::fs;
use std::io::Read;
use std::path::Path;

const MAX_FILE_SIZE_FOR_ENTROPY: u64 = 50 * 1024 * 1024; // 50 MB limit for entropy calculation

pub fn run_heuristics(path: &Path) -> ScanResult {
    let mut reasons = Vec::new();

    // Get file metadata
    let metadata = match path.metadata() {
        Ok(m) => m,
        Err(e) => {
            return ScanResult::error(
                path.to_path_buf(),
                format!("Failed to read file metadata: {}", e),
            );
        }
    };

    let file_size = metadata.len();

    // Rule 1: Zero-byte file with suspicious extension
    if file_size == 0 {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let suspicious_exts = [
            ".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".js", ".vbs", ".ps1",
            ".com", ".msi", ".jar", ".app", ".dex", ".so", ".dylib",
        ];
        if suspicious_exts.contains(&ext.as_str()) {
            reasons.push(format!(
                "Zero-byte file with suspicious extension '{}'",
                ext
            ));
        }
    }

    // Rule 2: Suspicious double extensions
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        let double_ext_patterns = [
            ".pdf.exe", ".doc.exe", ".jpg.exe", ".txt.exe", ".zip.exe",
            ".rar.scr", ".mp3.exe", ".avi.exe", ".png.exe",
        ];
        
        let filename_lower = filename.to_lowercase();
        for pattern in &double_ext_patterns {
            if filename_lower.contains(pattern) {
                reasons.push(format!(
                    "Suspicious double extension pattern detected: {}",
                    pattern
                ));
                break;
            }
        }
    }

    // Rule 3: Executable extension without valid PE header
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let exe_exts = [".exe", ".dll", ".scr", ".pif", ".sys"];
    if exe_exts.contains(&ext.as_str()) && file_size > 0 {
        // Read first 512 bytes to check PE header
        match read_file_bytes(path, 512) {
            Ok(data) => {
                if !is_pe_file(&data) {
                    reasons.push("Invalid PE header for executable extension".to_string());
                }
            }
            Err(e) => {
                reasons.push(format!("Failed to read file for PE check: {}", e));
            }
        }
    }

    // Rule 4: High entropy (likely packed/obfuscated)
    // Only calculate entropy for files smaller than the limit
    if file_size > 0 && file_size <= MAX_FILE_SIZE_FOR_ENTROPY {
        match read_file_bytes(path, file_size as usize) {
            Ok(data) => {
                let entropy = calculate_entropy(&data);
                if entropy > 7.2 {
                    reasons.push(format!(
                        "High entropy ({:.2}) – possible packer/obfuscation",
                        entropy
                    ));
                } else if entropy > 6.8 && exe_exts.contains(&ext.as_str()) {
                    // Lower threshold for executables
                    reasons.push(format!(
                        "Moderately high entropy ({:.2}) for executable",
                        entropy
                    ));
                }
            }
            Err(e) => {
                // Don't fail the scan, just note we couldn't calculate entropy
                eprintln!("Warning: Could not calculate entropy for {}: {}", path.display(), e);
            }
        }
    }

    // Rule 5: Suspicious file size patterns
    if file_size > 0 {
        // Very small executable (< 2KB) - suspicious
        if exe_exts.contains(&ext.as_str()) && file_size < 2048 {
            reasons.push(format!(
                "Unusually small executable file ({} bytes)",
                file_size
            ));
        }

        // Suspiciously large script files
        let script_exts = [".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh"];
        if script_exts.contains(&ext.as_str()) && file_size > 500_000 {
            reasons.push(format!(
                "Unusually large script file ({} bytes)",
                file_size
            ));
        }
    }

    // Rule 6: Hidden file with executable extension (Unix-like systems)
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        if filename.starts_with('.') && exe_exts.contains(&ext.as_str()) {
            reasons.push("Hidden file with executable extension".to_string());
        }
    }

    // Rule 7: Check for suspicious strings in script files
    let script_exts = [".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh"];
    if script_exts.contains(&ext.as_str()) && file_size > 0 && file_size < 1_000_000 {
        if let Ok(data) = read_file_bytes(path, file_size as usize) {
            if let Ok(content) = String::from_utf8(data) {
                let content_lower = content.to_lowercase();
                
                let suspicious_patterns = [
                    ("powershell", "downloadstring"),
                    ("invoke-expression", "iex"),
                    ("hidden", "windowstyle"),
                    ("bypass", "executionpolicy"),
                    ("wscript", "shell"),
                    ("cmd.exe", "/c"),
                ];

                for (pattern1, pattern2) in &suspicious_patterns {
                    if content_lower.contains(pattern1) && content_lower.contains(pattern2) {
                        reasons.push(format!(
                            "Suspicious script pattern detected: {} + {}",
                            pattern1, pattern2
                        ));
                        break;
                    }
                }
            }
        }
    }

    // Return result based on findings
    if !reasons.is_empty() {
        ScanResult::suspicious(path.to_path_buf(), reasons.join("; "))
    } else {
        ScanResult::clean(path.to_path_buf())
    }
}

/// Helper function to read a limited number of bytes from a file
fn read_file_bytes(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    
    // Use take() to limit the number of bytes read
    file.take(max_bytes as u64).read_to_end(&mut buffer)?;
    
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_zero_byte_exe() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_zero.exe");
        
        // Create zero-byte file
        fs::File::create(&test_file).unwrap();
        
        let result = run_heuristics(&test_file);
        assert!(result.reason.contains("Zero-byte"));
        
        // Cleanup
        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_double_extension() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("document.pdf.exe");
        
        // Create file with some content
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"dummy content").unwrap();
        
        let result = run_heuristics(&test_file);
        assert!(result.reason.contains("double extension"));
        
        // Cleanup
        let _ = fs::remove_file(&test_file);
    }
}