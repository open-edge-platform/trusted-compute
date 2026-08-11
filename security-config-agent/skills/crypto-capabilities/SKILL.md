---
name: crypto-capabilities
description: Report hardware crypto acceleration available on the CPU - AES-NI, SHA-NI, RDRAND, RDSEED. Use when asked which crypto instructions the platform supports.
metadata: { "openclaw": { "emoji": "🔑", "os": ["linux"] } }
---

# Hardware Crypto Capabilities Skill

## Purpose

This skill reports available hardware cryptographic acceleration features on the target system.

## What to Report

List of available/not available hardware crypto features:
- AES-NI (AES acceleration)
- SHA-NI (SHA acceleration)
- RDRAND (Hardware random number generator)
- RDSEED (Hardware entropy source)

## Commands

### Check CPU Crypto Features

```bash
# List all crypto-related CPU flags
grep -oE "aes|sha_ni|rdrand|rdseed" /proc/cpuinfo | sort -u
```

### Check Individual Features

```bash
# AES-NI
grep -w "aes" /proc/cpuinfo

# SHA-NI
grep -w "sha_ni" /proc/cpuinfo

# RDRAND
grep -w "rdrand" /proc/cpuinfo

# RDSEED
grep -w "rdseed" /proc/cpuinfo
```

## Output Format

```
HARDWARE CRYPTO CAPABILITIES
  AES-NI: Available / Not Available
  SHA-NI: Available / Not Available
  RDRAND: Available / Not Available
  RDSEED: Available / Not Available
```

## Dependencies

- Access to `/proc/cpuinfo`
