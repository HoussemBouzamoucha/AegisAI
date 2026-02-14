use sha2::{Sha256, Digest};
use std::{fs::File, io::{Read, BufReader}, path::Path};

pub fn compute_sha256(path: &Path) -> anyhow::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    let mut freq = [0usize; 256];
    for byte in data {
        freq[*byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in freq.iter() {
        if *count > 0 {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

pub fn is_pe_file(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
}

