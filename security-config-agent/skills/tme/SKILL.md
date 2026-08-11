---
name: tme
description: Report Intel Total Memory Encryption (TME/MKTME) support, activation state, and encryption algorithm. Use when asked about memory encryption on an Intel platform.
metadata:
  {
    "openclaw":
      {
        "emoji": "🧠",
        "os": ["linux"],
        "requires": { "bins": ["rdmsr"] }
      }
  }
---

# Intel TME Configuration Skill

## Purpose

This skill reports the current Intel Total Memory Encryption (TME) configuration on the target system.

## What to Report

- TME CPU support (Supported/Not Supported)
- TME status (Enabled/Disabled)
- Encryption algorithm in use

## Commands

### Check CPU Support

```bash
# Check cpuinfo for TME
grep -i "tme" /proc/cpuinfo

# Check via dmesg
dmesg | grep -i "tme"
```

### Check TME Status via MSR

```bash
# Read TME activation MSR (IA32_TME_ACTIVATE)
sudo modprobe msr
sudo rdmsr --bitfield 1:1 0x982   # TME enabled
sudo rdmsr --bitfield 7:4 0x982   # Encryption algorithm
```

**Interpreting Output:**
- `--bitfield 1:1` → 1 = TME enabled, 0 = disabled
- `--bitfield 7:4` → 0 = AES-XTS-128, 1 = AES-XTS-256

## Output Format

```
INTEL TME
  CPU Support: Yes/No
  Status: Enabled/Disabled
  Algorithm: AES-XTS-256 / AES-XTS-128 / Not Active
```

## Dependencies

- `msr-tools` package
- Root/sudo access

## Notes

TME requires:
- Intel Xeon Scalable (3rd Gen+) or Intel Core (11th Gen+)
- BIOS with TME option enabled
