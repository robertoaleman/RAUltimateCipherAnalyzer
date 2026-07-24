# RA Ultimate Cipher Analyzer, Rust version

A lightweight, high-performance Rust CLI tool and library for cryptographic, entropy, and structural analysis of binary payloads and file containers.

`RaUltimateCipherAnalyzer` inspects data to determine its density, distribution uniformity, and layout symmetry. It helps identify encryption status, structural metadata (such as O(1) index layers), and known magic signatures—distinguishing pure cryptographic ciphers from structured binary containers.

---

## Key Features

* **Segmented Slice Analysis (Header vs. Body):** Evaluates the first 512 bytes separately from the payload to detect structural asymmetry (e.g., control headers paired with compressed payloads).
* **Shannon Entropy Measurement:** Calculates information density in bits/byte (theoretical max: $8.0000$).
* **Chi-Square ($\chi^2$) Goodness-of-Fit Test:** Assesses byte distribution uniformity against a uniform target threshold ($p = 0.05, \text{critical value} < 293.25$).
* **Signature Matching:** Detects common file headers (OpenSSL, PGP, PKCS#1, PEM, ZIP, RAR, PDF) and native custom container layers (such as `PON` smart containers).
* **Base64 ASCII Stream Detection:** Automatically adjusts expectations when processing 6-bit Base64 encoded payload streams.
* **Block Boundary Alignment Check:** Evaluates byte-length modulo alignment against standard symmetric block sizes (8, 16, and 32 bytes).

---

## Diagnostic Output Breakdown

When running the analyzer on a binary container, the tool provides contextualized logging:

```text
=================================================================
               CRYPTOGRAPHIC ANALYSIS REPORT
=================================================================
 [METRIC] Total Analyzed Size: 2615217 bytes (2553.92 KB)
 [FORMAT] Encoding Detected: Raw Binary Byte Stream.
 [METRIC] Global Shannon Entropy: 7.8108 bits/byte (Max: 8.0000)
 [SEGMENT] Header (First 512B) -> Entropy: 6.3398 | Chi-Square: 8176.00
 [SEGMENT] Body Payload        -> Entropy: 7.8109 | Chi-Square: 2645416.09
 [EVAL] Structural Asymmetry: Header and Body exhibit distinct density profiles (typical of indexed containers).
 [METRIC] Global Chi-Square: 2648951.09 (Uniform Target: < 293.25)
 [EVAL] Distribution: Non-uniform / Structured (Presence of lookup indexes, metadata headers, or record markers).
 [MATCH] Identified Signatures: PON Smart Container / Optimization Layer Header
=================================================================


```


```text
+-----------------------+---------------------+----------------------------------------------------------------------------------+
| Metric                | Threshold / Value   | Interpretation                                                                   |
+-----------------------+---------------------+----------------------------------------------------------------------------------+
| Shannon Entropy       | > 7.90 bits/byte    | Typical of strong symmetric/asymmetric encryption streams (AES, RSA, ChaCha20). |
|                       | 7.20 - 7.89 bits/b  | High-density data; typical of compressed containers, packed binaries, or indexes.|
|                       | < 7.20 bits/byte    | Structured text, source code, executables, or weak transposition ciphers.        |
+-----------------------+---------------------+----------------------------------------------------------------------------------+
| Chi-Square (X^2)      | < 293.25            | Uniform byte distribution. Indicates true pseudorandom output (strong ciphers).  |
|                       | > 293.25            | Non-uniform distribution. Indicates structured layouts, offsets, or byte skew. |
+-----------------------+---------------------+----------------------------------------------------------------------------------+
| Header vs. Body Delta | Asymmetric          | Indicates an unencrypted/structured index header paired with a high-density body.|
+-----------------------+---------------------+----------------------------------------------------------------------------------+
```

**Quick Start

Prerequisites

Ensure you have Rust and cargo installed

rustc --version
cargo --version

**Usage:
Run the binary against any target file:Bash./target/release/ra_cipher_analyzer path/to/target_file.bin
Or pass a path via cargo run:Bashcargo run --release -- sample.bin
Code ExampleIntegrating the analyzer as a module in your own project:Rustuse ra_cipher_analyzer::RaUltimateCipherAnalyzer;
use std::path::Path;

fn main() {
    let analyzer = RaUltimateCipherAnalyzer::new();
    let file_path = Path::new("payload.bin");

    match analyzer.analyze_file(file_path) {
        Ok(report_lines) => {
            for line in report_lines {
                println!("{}", line);
            }
        }
        Err(err) => eprintln!("Analysis failed: {}", err),
    }
}


## License & Legal Disclaimer

### Open Source License
This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the `LICENSE` file for full details.

---

### Important Legal & Usage Disclaimer

> **IMPORTANT: PLEASE READ CAREFULLY BEFORE USING THIS TOOL**

This tool, **RA Ultimate Cipher Analyzer**, is provided **solely for educational, research, and authorized security testing purposes**. It is intended to assist security professionals and researchers in analyzing encrypted files with proper authorization.

* **PROHIBITED USE:** Use of this tool for any illegal or unauthorized activity is **strictly prohibited**. The developer is not responsible for any misuse or damages caused by this software.
* **USER RESPONSIBILITY:** You **assume full responsibility** for the consequences of using this tool. 
* **LIMITATION OF GUARANTEE:** The accuracy of cipher identification and statistical heuristics is not guaranteed, and results should be interpreted with caution as diagnostic indicators rather than definitive cryptanalysis.

By using this tool, you agree to comply with all applicable laws and regulations and acknowledge that you have read and understood this disclaimer in its entirety. **If you do not agree to these terms, do not use this tool.**

---

## Contact & Support

Found an issue or have a feature suggestion? 
* Open an issue on GitHub.
* Contact us at [ventics.com](https://ventics.com).
