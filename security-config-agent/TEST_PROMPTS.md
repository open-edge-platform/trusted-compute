# Security Configuration Agent - Test Prompts


## secure-boot

Trigger prompts:

1. `Is Secure Boot enabled on this machine?`
2. `Report the UEFI Secure Boot configuration.`
3. `Check the secure boot state before I install anything.`


---

## boot-guard

Trigger prompts:

1. `What Boot Guard profile is this platform provisioned with?`
2. `Is Intel Boot Guard enabled?`
3. `Do we have Verified Boot and Measured Boot turned on?`
4. `Show me the firmware root of trust status for this system.`
5. `Report Intel Boot Guard configuration`

---

## tme

Trigger prompts:

1. `Is Total Memory Encryption active on this server?`
2. `Report Intel TME status and the encryption algorithm.`
3. `Is my system RAM encrypted?`
4. `Check memory encryption before we deploy confidential workloads.`


---

## disk-encryption

Trigger prompts:

1. `Are the disks on this system encrypted?`
2. `Show me the LUKS volumes and their cipher and key size.`
3. `List any unencrypted partitions I should worry about.`
4. `What dm-crypt mappings are active right now?`

---

## crypto-capabilities

Trigger prompts:

1. `Which hardware crypto instructions does this CPU support?`
2. `Do we have AES-NI and SHA-NI available?`
3. `Is RDRAND and RDSEED present?`

---

## trusted-compute-install

Trigger prompts (install):

1. `Install Trusted Compute on this machine using K3s.`
2. `Deploy the Trusted Compute stack with Docker.`



