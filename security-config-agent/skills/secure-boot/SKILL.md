---
name: secure-boot
description: Report UEFI Secure Boot configuration on an Intel edge platform - enabled state, Setup Mode, and enrolled PK/KEK/db keys. Use when asked about Secure Boot status or boot chain key enrollment.
metadata:
  {
    "openclaw":
      {
        "emoji": "🔒",
        "os": ["linux"],
        "requires": { "bins": ["mokutil"] }
      }
  }
---

# Secure Boot Configuration Skill

## Purpose

This skill reports the current UEFI Secure Boot configuration on the target system.

## What to Report

- Secure Boot status (Enabled/Disabled)
- Setup Mode status (Enabled/Disabled)
- Platform Key (PK) presence
- Key Exchange Keys (KEK) enrolled
- Signature database (db) entries

## Commands

### Check Secure Boot Status

```bash
# Check if Secure Boot is enabled
mokutil --sb-state

# Alternative: Check EFI variable directly.
# The first 4 bytes are the EFI attributes header, so skip them and read 1 data byte.
cat /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | od -An -t u1 -j 4 -N 1 | tr -d ' '
```

**Interpreting Output:**
- `SecureBoot enabled` → Secure Boot is active
- Data byte value `1` → Enabled, `0` → Disabled

### Check Setup Mode

```bash
mokutil --sb-state | grep -i "setup mode"

# Alternative: Check EFI variable directly.
# The first 4 bytes are the EFI attributes header, so skip them and read 1 data byte.
cat /sys/firmware/efi/efivars/SetupMode-* 2>/dev/null | od -An -t u1 -j 4 -N 1 | tr -d ' '
```

**Interpreting Output:**
- Value `0` → Setup Mode disabled (normal operation)
- Value `1` → Setup Mode enabled (keys can be modified)

### Check Secure Boot Keys

```bash
# Platform Key (PK)
mokutil --pk

# Key Exchange Keys (KEK)
mokutil --kek

# Signature database (db)
mokutil --db

# List all enrolled keys
mokutil --list-enrolled
```

## Output Format

```
SECURE BOOT
  Status: Enabled/Disabled
  Setup Mode: Enabled/Disabled
  Platform Key (PK): Present/Not Found
  Key Exchange Keys (KEK): X enrolled
  Signature Database (db): X entries
```

## Dependencies

- `mokutil` package
- EFI boot mode (not legacy BIOS)
- Access to `/sys/firmware/efi/` filesystem
