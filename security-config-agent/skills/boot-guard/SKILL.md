---
name: boot-guard
description: Report Intel Boot Guard provisioning state, profile (0, 3, 4, or 5), and Verified/Measured Boot modes. Use when asked about Boot Guard, BtG profiles, or firmware root of trust.
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "os": ["linux"],
        "requires": { "bins": ["rdmsr", "tpm2_pcrread"] }
      }
  }
---

# Intel Boot Guard Configuration Skill

## Purpose

This skill reports the current Intel Boot Guard configuration on the target system.

## What to Report

- Boot Guard provisioning status (Provisioned/Not Provisioned)
- Profile number (0, 3, 4, or 5)
- Verified Boot mode (Enabled/Disabled)
- Measured Boot mode (Enabled/Disabled)

## Background

### Boot Guard Profiles

| Profile | Verified Boot | Measured Boot | Description |
|---------|--------------|---------------|-------------|
| 0 | No | No | Not provisioned |
| 3 | No | Yes | Measured Boot only |
| 4 | Yes | No | Verified Boot only |
| 5 | Yes | Yes | Verified + Measured Boot |

## Commands

### Read Boot Guard MSR

```bash
# Load MSR module
sudo modprobe msr

# Read Measured (bit 5) and Verified (bit 6) Boot bits together
sudo rdmsr --bitfield 6:5 0x13A

```

**Interpreting `--bitfield 6:5` output:**

| Value | Verified Boot | Measured Boot | Profile |
|-------|--------------|---------------|---------|
| 0 | Disabled | Disabled | 0 |
| 1 | Disabled | Enabled | 3 |
| 2 | Enabled | Disabled | 4 |
| 3 | Enabled | Enabled | 5 |

### Check PCR0 (Boot Guard measurements)

```bash
tpm2_pcrread sha256:0
```

## Output Format

```
INTEL BOOT GUARD
  Status: Provisioned/Not Provisioned
  Profile: 5 (Verified + Measured Boot)
  Verified Boot: Enabled/Disabled
  Measured Boot: Enabled/Disabled
  PCR0: Has measurements / Empty
```

## Dependencies

- `msr-tools` package (for rdmsr)
- `tpm2-tools` package
- Root/sudo access

## Notes

Boot Guard is provisioned at manufacturing by the OEM. It cannot be enabled by the end user after system manufacture.
