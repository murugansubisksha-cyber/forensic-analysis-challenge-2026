Forensic Analysis Challenge 2026

Overview

This repository contains the analysis code and documentation for a three-part forensic investigation involving:

1. Static malware triage
2. Endpoint and web-activity analysis
3. Audio processing and transcription

The investigation is performed in an isolated analysis environment.

Challenges

Challenge 1: Static Malware Triage

Static analysis of provided artifacts without executing samples.

Analysis includes:

- File hashes
- PE structure
- Sections
- Imports
- Exports
- Strings
- Entropy
- Digital-signature indicators
- Malware capability indicators
- Passive hash-based intelligence

Relevant MITRE ATT&CK technique:

- T1574.002: DLL Side-Loading, where supported by evidence

Challenge 2: Endpoint Investigation

Analysis of endpoint security, web activity and USB event logs.

The investigation examines:

- Malicious detections
- Affected endpoints
- Repeated file hashes
- Web activity preceding detections
- USB-event correlations
- Per-endpoint timelines

The analysis distinguishes between detection, temporal correlation and confirmed execution.

Challenge 3: Audio Analysis

Processing and analysis of an intercepted audio recording.

The workflow includes:

- Original-audio preservation
- Noise reduction
- Speech enhancement
- Transcription
- Manual verification
- Identification of uncertain words

Repository Structure

forensic-analysis-challenge-2026/
├── challenge1/
├── challenge2/
├── challenge3/
├── docs/
├── screenshots/
├── notes/
├── out/
├── evidence/
├── requirements.txt
├── .gitignore
└── README.md

Evidence Handling

Original evidence is not committed to this repository.

Samples and suspicious artifacts are analyzed only in an isolated environment.

Suspicious domains, IP addresses and malware samples are not directly accessed or executed.

Reproducibility

The analysis scripts are designed to process the provided evidence and generate supporting outputs for the final investigation report.

Disclaimer

This repository contains analysis tooling and documentation only. Evidence files, malware samples, audio files and other potentially sensitive artifacts are intentionally excluded.