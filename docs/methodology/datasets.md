# Dataset Methodology & Separation Policy

## Dataset Separation Policy
The project maintains **UNSW-NB15** and **CICIDS2017** as strictly independent datasets. Label taxonomies and feature spaces are NOT combined.

## 1. CICIDS2017 Benchmark
- **Features**: 70 quantitative network flow attributes (IAT, packet lengths, window sizes, flags).
- **Test Samples**: 383,203 test samples.
- **Classes (15)**: BENIGN, Bot, DDoS, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, Heartbleed, Infiltration, PortScan, SSH-Patator, Web Attack - Brute Force, Web Attack - SQL Injection, Web Attack - XSS.

## 2. UNSW-NB15 Benchmark
- **Features**: 42 network flow attributes.
- **Test Samples**: 82,332 test samples.
- **Classes (10)**: Normal, Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, Worms.
