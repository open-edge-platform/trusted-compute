---
name: disk-encryption
description: Report disk encryption configuration - LUKS/dm-crypt volumes, cipher and key size, swap encryption, and unencrypted volumes. Use when asked whether disks or swap are encrypted.
metadata:
  {
    "openclaw":
      {
        "emoji": "💽",
        "os": ["linux"],
        "requires": { "bins": ["lsblk", "dmsetup", "cryptsetup"] }
      }
  }
---

# Disk Encryption Configuration Skill

## Purpose

This skill reports the current disk encryption configuration on the target system.

## What to Report

- Encrypted volumes and their mount points
- Encryption method (LUKS, LUKS2, dm-crypt)
- Cipher and key size in use
- Swap encryption status
- Unencrypted volumes

## Commands

### List Block Devices

```bash
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
```

### Check for LUKS Volumes

```bash
# List active encrypted mappings
ls -la /dev/mapper/

# Check dm-crypt targets
sudo dmsetup table --target crypt
```

### Get LUKS Details

```bash
# For a specific LUKS device
sudo cryptsetup luksDump /dev/sdXn
```

**Key fields to report:**
- Version (LUKS1/LUKS2)
- Cipher (e.g., aes-xts-plain64)
- Key size (e.g., 512 bits)

### Check Swap Encryption

```bash
swapon --show
cat /etc/crypttab | grep swap
```

## Output Format

```
DISK ENCRYPTION
  Encrypted Volumes:
    /dev/nvme0n1p3: LUKS2 (aes-xts-plain64, 512-bit) → /
    /dev/nvme0n1p4: LUKS2 (aes-xts-plain64, 512-bit) → /home
  Swap: Encrypted / Not Encrypted / No Swap
  Unencrypted Volumes:
    /dev/nvme0n1p1: EFI System Partition (expected)
```

## Dependencies

- `cryptsetup` package
- `dmsetup` utility
- `lsblk` utility
- Root/sudo access for LUKS details
