# 😈 EVM Wallet Cracker / Hunter
[![Download Executable](https://img.shields.io/badge/Download_Executable-v1.0.0-blue?style=for-the-badge&logo=linux)](https://github.com/reimen-cpu/Seed-Cracking/releases/latest/download/seed-cracker) 🎯

A high-performance, CUDA-accelerated brute-force tool designed to recover lost or forgotten BIP-39 seed phrases for EVM-compatible wallets.

## ⚠️ Disclaimer

**This tool is for educational and forensic purposes ONLY.** Unauthorized use against wallets you do not own is illegal and unethical. The probability of finding a random active wallet is effectively zero due to the astronomical search space (2^128 to 2^256).

## 🚀 Key Features

- **Extreme Speed**: Leverages NVIDIA GPUs via CUDA to perform thousands of derivations per second.
- **Support for Partial Phrases**: Use `?` as a placeholder for unknown words in a 12 or 24-word seed phrase.
- **100% GPU Mode**: Capable of running the entire pipeline (PBKDF2, HMAC, BIP-32, secp256k1) on the GPU to eliminate CPU bottlenecks.
- **Hybrid Mode**: Optional CPU+GPU execution for older configurations or specific recovery scenarios.
- **Target Tracking**: Monitors a list of target addresses and alerts instantly upon a match.

## 🛠 Prerequisites

- **Python 3.x**
- **NVIDIA GPU** with CUDA support.
- **CUDA Toolkit** (for compiling the binary).
- **Wordlist**: Requires the `bip39.txt` dictionary in the same directory.

## 📦 Compilation

To compile the cracker binary, run:
```bash
make
```
This will generate the `wallet-cracker` (hybrid) or `wallet-cracker-gpu` (full-gpu) executable.

## 🖥 Usage

### Graphical User Interface
Launch the dashboard:
```bash
python3 wallet-cracker.py
```

### Configuration
1. **Target List**: Provide a `.txt` file with one Ethereum address per line (the wallets you want to find).
2. **Partial Phrase**: Enter your known words and use `?` for missing ones (e.g., `word1 word2 ? word4 ...`).
3. **Parallelism**: Adjust the batch size/hreads based on your GPU VRAM.
4. **Start**: Hit "Iniciar Búsqueda" to begin the hunt.

## ⚙️ Technical Details

- **BIP-39**: Seed generation from mnemonic.
- **BIP-32/44**: Hierarchical derivation path `m/44'/60'/0'/0/0`.
- **secp256k1**: GPU-optimized elliptic curve arithmetic.
- **Keccak-256**: Fast GPU implementation for EVM address calculation.
