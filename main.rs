use base64::prelude::*;
use std::env;
use std::fs;
use std::path::Path;

struct EntropyEntry {
    cipher: &'static str,
    format: &'static str,
    expected_entropy: &'static str,
    notes: &'static str,
}

pub struct RaUltimateCipherAnalyzer {
    entropy_table: Vec<EntropyEntry>,
}

impl RaUltimateCipherAnalyzer {
    pub fn new() -> Self {
        Self {
            entropy_table: vec![
                EntropyEntry { cipher: "AES (128/192/256)", format: "Binary", expected_entropy: "7.90 - 8.00", notes: "High uniform distribution, typical of cryptographic pseudorandom streams." },
                EntropyEntry { cipher: "PON-DB / Smart Container", format: "Binary", expected_entropy: "7.20 - 7.85", notes: "Encapsulated index + high-density payload container." },
                EntropyEntry { cipher: "AES (128/192/256)", format: "Base64", expected_entropy: "5.50 - 6.00", notes: "Entropy bounded by the 64-character ASCII encoding space." },
                EntropyEntry { cipher: "RSA / Asymmetric", format: "Binary", expected_entropy: "7.80 - 8.00", notes: "Encrypted payload or DER-encoded public key signatures." },
                EntropyEntry { cipher: "Plaintext / Structured", format: "Binary/Text", expected_entropy: "< 6.00", notes: "Predictable byte distribution with high linguistic/syntactic redundancy." },
            ],
        }
    }

    fn is_base64(&self, data: &[u8]) -> bool {
        let trimmed = match std::str::from_utf8(data) {
            Ok(s) => s.trim(),
            Err(_) => return false,
        };

        if trimmed.is_empty() {
            return false;
        }

        let is_valid_chars = trimmed.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        });

        is_valid_chars && BASE64_STANDARD.decode(trimmed).is_ok()
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0usize; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &freq in &frequency {
            if freq > 0 {
                let p = freq as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn byte_distribution(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0usize; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let expected = data.len() as f64 / 256.0;
        let mut chi_square = 0.0;

        for &freq in &frequency {
            let diff = freq as f64 - expected;
            chi_square += (diff * diff) / expected;
        }

        chi_square
    }

    fn check_for_known_patterns(&self, data: &[u8], is_base64: bool) -> Option<String> {
        let mut matches = Vec::new();

        // Custom / Native Magic Signatures
        if data.starts_with(b"PON") || data.starts_with(&[0x50, 0x4F, 0x4E]) {
            matches.push("PON Smart Container / Optimization Layer Header");
        }
        if data.starts_with(b"Salted__") {
            matches.push("OpenSSL Encrypted Header ('Salted__')");
        }
        if data.starts_with(&[0x99, 0x01]) || data.starts_with(&[0x85, 0x02]) {
            matches.push("PGP/GPG Encrypted Message/Key Packet");
        }
        if data.starts_with(&[0x30, 0x82]) {
            matches.push("PKCS#1 / DER Encrypted Structure");
        }
        if data.starts_with(b"-----BEGIN ENCRYPTED DATA-----") {
            matches.push("PEM Encrypted Data Container");
        }
        if data.starts_with(b"PK\x03\x04") && data.len() > 6 && (data[6] & 1) == 1 {
            matches.push("Encrypted ZIP Archive Header");
        }
        if data.starts_with(b"%PDF-") && data.windows(8).any(|w| w == b"/Encrypt") {
            matches.push("PDF Document with /Encrypt Structure");
        }

        if is_base64 {
            if let Ok(utf8_str) = std::str::from_utf8(data) {
                if let Ok(decoded) = BASE64_STANDARD.decode(utf8_str.trim()) {
                    if decoded.starts_with(b"PON") {
                        matches.push("Decoded Base64 -> PON Smart Container Header");
                    } else if decoded.starts_with(&[0x30, 0x82]) {
                        matches.push("Decoded Base64 -> PKCS#1 DER Structure");
                    }
                }
            }
        }

        if matches.is_empty() {
            None
        } else {
            Some(format!("[MATCH] Identified Signatures: {}", matches.join(" | ")))
        }
    }

    pub fn analyze_data(&self, data: &[u8]) -> Vec<String> {
        let mut logs = Vec::new();
        let file_size = data.len();

        logs.push(format!("[METRIC] Total Analyzed Size: {} bytes ({:.2} KB)", file_size, file_size as f64 / 1024.0));

        if file_size < 1024 {
            logs.push("[WARN] Sample size under 1 KB: Statistical metrics may show variance.".to_string());
        }

        let is_base64 = self.is_base64(data);
        if is_base64 {
            logs.push("[FORMAT] Encoding Detected: Base64 ASCII text stream.".to_string());
        } else {
            logs.push("[FORMAT] Encoding Detected: Raw Binary Byte Stream.".to_string());
        }

        // --- GLOBAL METRICS ---
        let global_entropy = self.calculate_entropy(data);
        logs.push(format!("[METRIC] Global Shannon Entropy: {:.4} bits/byte (Max: 8.0000)", global_entropy));

        // --- SLICE ANALYSIS (Header vs. Body) ---
        if file_size >= 512 && !is_base64 {
            let header_slice = &data[..512];
            let body_slice = &data[512..];

            let header_entropy = self.calculate_entropy(header_slice);
            let body_entropy = self.calculate_entropy(body_slice);

            let header_chi = self.byte_distribution(header_slice);
            let body_chi = self.byte_distribution(body_slice);

            logs.push(format!(
                "[SEGMENT] Header (First 512B) -> Entropy: {:.4} | Chi-Square: {:.2}",
                header_entropy, header_chi
            ));
            logs.push(format!(
                "[SEGMENT] Body Payload        -> Entropy: {:.4} | Chi-Square: {:.2}",
                body_entropy, body_chi
            ));

            // Diagnosis based on Delta
            let entropy_delta = (header_entropy - body_entropy).abs();
            if entropy_delta > 0.5 {
                logs.push("[EVAL] Structural Asymmetry: Header and Body exhibit distinct density profiles (typical of indexed containers).".to_string());
            } else {
                logs.push("[EVAL] Structural Symmetry: Homogeneous density across Header and Body payload.".to_string());
            }
        }

        // --- CHI-SQUARE EVALUATION ---
        if !is_base64 {
            let chi_square = self.byte_distribution(data);
            logs.push(format!("[METRIC] Global Chi-Square: {:.2} (Uniform Target: < 293.25)", chi_square));
            if chi_square < 293.25 {
                logs.push("[EVAL] Distribution: Uniform / Unpredictable (Cryptographic cipher output).".to_string());
            } else {
                logs.push("[EVAL] Distribution: Non-uniform / Structured (Presence of lookup indexes, metadata headers, or record markers).".to_string());
            }
        }

        if let Some(pattern_msg) = self.check_for_known_patterns(data, is_base64) {
            logs.push(pattern_msg);
        } else {
            logs.push("[MATCH] Known Magic Signatures: None identified in payload header.".to_string());
        }

        logs
    }

    pub fn analyze_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<String>, std::io::Error> {
        let data = fs::read(path)?;
        Ok(self.analyze_data(&data))
    }
}

fn main() {
    let analyzer = RaUltimateCipherAnalyzer::new();
    let args: Vec<String> = env::args().collect();

    let file_path = if args.len() > 1 {
        &args[1]
    } else {
        "10k.pon"
    };

    println!(">>> Ejecutando diagnóstico avanzado para: {}\n", file_path);

    match analyzer.analyze_file(file_path) {
        Ok(results) => {
            println!("=================================================================");
            println!("               REPORTE DE ANÁLISIS CRIPTOGRÁFICO                 ");
            println!("=================================================================");
            for line in results {
                println!(" {}", line);
            }
            println!("=================================================================");
        }
        Err(e) => {
            eprintln!("[ERROR] Fallo al abrir o procesar el archivo '{}': {}", file_path, e);
        }
    }
}