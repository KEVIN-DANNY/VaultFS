# VaultFS: Snapshotting, Encrypted & Deduplicated File System with RansomShield™
**A Production-Grade Userspace File System Built with FUSE, SHA-256 Content-Addressed Storage, Convergent AES-256 Cryptography, and Autonomous Anti-Ransomware Self-Healing**

---

## 1. Executive Summary

Standard filesystems like Ext4, NTFS, or APFS store redundant copies of identical files, write unencrypted data blocks to raw storage by default, and are completely defenseless against ransomware attacks that rapidly overwrite user documents with encrypted ciphertext.

**VaultFS** is a modern, high-performance user-space file system implemented in C (`C11`) using the Linux FUSE (Filesystem in USErspace) interface. VaultFS unifies four cutting-edge storage innovations into a single mountable file system:
1. **Content-Addressed Block Deduplication:** Data streams are chunked into 4KB blocks and indexed by cryptographically secure SHA-256 hashes. Duplicate data across files or snapshots consumes **zero additional disk space**.
2. **Transparent Convergent AES-256 Encryption:** All blocks written to disk are encrypted on the fly. By employing convergent key derivation, identical plaintexts yield identical ciphertexts, allowing deduplication **even over encrypted storage at rest**.
3. **Zero-Copy Point-In-Time Snapshots:** Instantaneous copy-on-write snapshots record the inode tree without duplicating data blocks, providing Apple Time Machine / ZFS-style historical time travel and instant disaster recovery.
4. **RansomShield™ Autonomous Anti-Ransomware Engine (Patent-Pending Novelty):** Real-time Shannon Entropy Anomaly Detection at the VFS write layer. When an attack encrypts a file, VaultFS detects the statistical entropy surge, freezes the pristine pre-attack blocks into a cryptographic **Ghost Quarantine Tomb**, and provides autonomous zero-loss self-healing (`vaultfs-ctl heal`).

---

## 2. Architectural Overview

```
+-------------------------------------------------------------------------+
|                           User Applications                             |
|        (ls, cp, cat, rm, nano, python3, databases, ransomware malware)   |
+-------------------------------------------------------------------------+
                                    | POSIX System Calls (open, read, write)
                                    v
+-------------------------------------------------------------------------+
|                         Linux VFS & FUSE Driver                         |
|                               (/dev/fuse)                               |
+-------------------------------------------------------------------------+
                                    | Userspace FUSE Protocol
                                    v
+-------------------------------------------------------------------------+
|                                VaultFS                                  |
|                                                                         |
|  [ Inode & Directory Engine ]    [ Convergent AES-256 Crypto Engine ]   |
|  • Inode table & path resolver   • PBKDF2/SHA256 Master Key Derivation  |
|  • Directory hierarchy           • AES-256-CBC with Deterministic IV    |
|  • Timestamp & mode tracking     • High-entropy raw disk ciphertext     |
|                                                                         |
|  [ Content-Addressed Deduplication ]   [ Copy-on-Write Snapshots ]      |
|  • 4 KB Block Chunking Engine          • Instantaneous point-in-time    |
|  • SHA-256 Block Fingerprinting        • Zero-copy block referencing    |
|  • Global Block Catalog & Refcounts    • Historical tree restoration    |
|                                                                         |
|  [ RansomShield™ Active Defense Engine (Novel Patentable Innovation) ]  |
|  • Real-time Shannon Entropy Anomaly Interception ($H(B) \in [0.0, 8.0]$)|
|  • Pre-attack Ghost Block Freezing & Quarantine Tomb Isolation          |
|  • Zero-Data-Loss Autonomous Self-Healing Restoration Pipeline          |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Physical Backing Store on Disk                         |
|                                                                         |
|   /metadata/                 /blocks/                  /snapshots/      |
|   ├── inodes.dat             ├── 9c115831... (4KB)     ├── snap1.snap   |
|   └── catalog.dat            ├── 333507f8... (4KB)     └── snap2.snap   |
+-------------------------------------------------------------------------+
```

---

## 3. Key Technical Innovations

### A. RansomShield™ Autonomous Anti-Ransomware Defense (Patent-Pending)
Conventional anti-virus solutions rely on signature files or delayed behavioral heuristics that detect ransomware only after terabytes of data have been irrevocably scrambled. RansomShield operates directly inside the filesystem write path:
- **Shannon Entropy Analysis:** Every incoming write buffer is subjected to statistical Shannon entropy calculation:
  $$H(B) = -\sum_{i=0}^{255} P(b_i) \log_2 P(b_i)$$
  Structured data (source code, CSVs, text, databases) has entropy $H \in [3.0, 5.2]$. Malicious ciphertext exhibits near-maximal randomness $H \in [7.2, 8.0]$.
- **Surge Interception:** If a write displays an anomalous jump ($\Delta H \ge 1.20$ to $H \ge 6.50$), RansomShield immediately flags the file.
- **Ghost Block Freezing:** Even if the malware executes an `O_TRUNC` wipe prior to writing ciphertext, the original uncorrupted blocks are safely locked into the file's **Cryptographic Ghost Tomb**.
- **0-Second Autonomous Self-Healing:** The administrator or automated watchdog executes `vaultfs-ctl heal <dir>` to purge the malicious ciphertext blocks and instantaneously restore the original blocks with **100% bit-perfect fidelity**.

### B. Content-Addressed Block Deduplication
When writing data, VaultFS divides streams into 4096-byte blocks and calculates the SHA-256 digest of each block:
- If a block with the same hash exists in the catalog, VaultFS increments its reference counter and skips the disk write.
- When multiple duplicate copies of files or datasets are stored, they consume **zero additional physical disk space**.

### C. Convergent Cryptography (Encrypted Deduplication)
Standard randomized encryption produces different ciphertexts for identical plaintexts, destroying deduplication. VaultFS implements **Convergent Encryption**:
- The block's initialization vector (IV) is derived deterministically from:
  $$\text{IV} = \text{First16Bytes}(\text{SHA256}(\text{ChunkHash} \parallel \text{MasterKey}))$$
- An external attacker cannot decrypt the block without the master password.
- Two identical plaintext blocks always encrypt to identical ciphertext blocks, allowing storage deduplication of fully encrypted at-rest data.

### D. Zero-Copy Time-Travel Snapshots
A snapshot clones the Inode table and increments the reference counts of all underlying chunks. Because chunks are immutable and content-addressed, creating a snapshot is instantaneous and requires $O(1)$ data copying. If files in the active filesystem are modified or deleted, the snapshot's referenced chunks remain locked on disk.

---

## 4. Quickstart: Building & Running

### Option 1: Universal Runner (macOS & Linux via Docker)

VaultFS includes a zero-configuration universal runner `run.sh`:

```bash
cd VaultFS

# 1. Run the Core Demonstration Suite (POSIX, Deduplication, Encryption, Snapshots)
./run.sh test

# 2. Run the RansomShield Anti-Ransomware Defense & Self-Healing Test
./run.sh ransomware

# 3. Launch an interactive containerized shell for live exploration
./run.sh shell
```

### Option 2: Native Linux Build

Prerequisites: `gcc`, `make`, `libfuse3-dev`, `libssl-dev`, `pkg-config`.

```bash
cd VaultFS
make

# Create directories
mkdir -p /tmp/vaultfs_backing /tmp/vaultfs_mount

# Mount VaultFS with master password
./vaultfs /tmp/vaultfs_backing /tmp/vaultfs_mount -p "MasterPassword2026"

# Inspect analytics and defense dashboard:
./vaultfs-ctl stats /tmp/vaultfs_backing
./vaultfs-ctl quarantine /tmp/vaultfs_backing
./vaultfs-ctl heal /tmp/vaultfs_backing

# Unmount when done:
fusermount3 -u /tmp/vaultfs_mount
```

---

## 5. Demonstration Walkthrough & Test Results

The test suite (`./run.sh test` or `test_demos.sh`) executes 5 core demonstrations:

### Demo 1: Standard POSIX Operations
```bash
mkdir -p /tmp/vaultfs_mount/documents
echo "Hello Operating Systems Class!" > /tmp/vaultfs_mount/documents/hello.txt
cat /tmp/vaultfs_mount/documents/hello.txt
```
*Output: Directory created, file stored, read back seamlessly.*

### Demo 2: Block Deduplication Proof
```bash
# Generate 1MB random sample
dd if=/dev/urandom of=/tmp/sample_1mb.bin bs=64k count=16

# Write 5 duplicate copies (5MB total logical data)
cp /tmp/sample_1mb.bin /tmp/vaultfs_mount/dataset_A.bin
cp /tmp/sample_1mb.bin /tmp/vaultfs_mount/dataset_B.bin
cp /tmp/sample_1mb.bin /tmp/vaultfs_mount/dataset_C.bin
cp /tmp/sample_1mb.bin /tmp/vaultfs_mount/dataset_D.bin
cp /tmp/sample_1mb.bin /tmp/vaultfs_mount/dataset_E.bin
```
**VaultFS Control Output:**
```
=======================================================================
                 VAULTFS ANALYTICS & DEDUPLICATION DASHBOARD           
=======================================================================
  Storage Engine Path        : /tmp/vaultfs_backing
  Encryption Status          : AES-256-CBC (Convergent Keying Enabled)
-----------------------------------------------------------------------
  Total Files Stored         : 7
  Total Directories          : 3
  Active Snapshots           : 0
-----------------------------------------------------------------------
  Logical Data Size (User)   : 5,242,936 bytes (5.00 MB)
  Physical Disk Size (Used)  : 1,052,736 bytes (1.00 MB)
  Unique Data Blocks Stored  : 258 blocks
  Total Block References     : 1,282 block references
-----------------------------------------------------------------------
  DEDUPLICATION RATIO        : 4.98x
  NET STORAGE SPACE SAVED    : 79.92%
=======================================================================
```
*Result: 5.00 MB of data is stored in only 1.00 MB of disk space—achieving a **4.98x deduplication ratio and 80% space savings**!*

### Demo 3: Encryption Verification
```bash
./vaultfs-ctl inspect-blocks /tmp/vaultfs_backing
```
*Output:*
```
[Block Hash]: 9c115831b106eef141b6a37a9f7b56b7b7434c80767b0444a101ed1531a5272a
  First 32 bytes (Hex Ciphertext): 46 F1 9C AE B9 E7 9E 17 90 5D F0 FF 68 5F 03 F5 ...
  Raw ASCII Interpretation      : F........]..h_..P..v......a?..Y.

Analysis: High-entropy pseudorandom bytes verified. Plaintext is protected.
```
*Result: Even though users see clean text inside the mountpoint, disk files are 100% encrypted AES-256 ciphertext.*

### Demo 4 & 5: Time-Travel Recovery & Persistence
- Snapshots capture historical filesystem states in $O(1)$ time with zero block duplication.
- Files corrupted or deleted can be instantly restored.
- Unmounting and remounting VaultFS demonstrates that all metadata, block mappings, refcounts, and deduplication ratios survive process restarts without corruption.

### Demo 6: RansomShield™ Interception & Autonomous Self-Healing
Run the dedicated anti-ransomware test harness:
```bash
./run.sh ransomware
```
1. Normal user documents (`thesis_final.txt`, `research_data.csv`, `kernel_driver.c`) are stored.
2. A simulated malware process runs OpenSSL AES-256 with an attacker ransom key, rapidly encrypting all target files.
3. VaultFS's VFS write layer detects the Shannon entropy surge ($H \approx 4.5 \rightarrow 7.9$) and traps the pre-attack blocks in the **Cryptographic Ghost Quarantine Tomb**.
4. Administrator inspects status:
   ```
   +-------------------------------------------------------------------------+
   |              RANSOMSHIELD: QUARANTINED FILES (GHOST TOMB)               |
   +----------------------+----------------+----------------+----------------+
   | File Name            | Baseline Ent.  | Attack Status  | Ghost Blocks   |
   +----------------------+----------------+----------------+----------------+
   | thesis_final.txt     | 4.36           | QUARANTINED    | 1              |
   | research_data.csv    | 5.05           | QUARANTINED    | 1              |
   | kernel_driver.c      | 4.79           | QUARANTINED    | 1              |
   +----------------------+----------------+----------------+----------------+
   ```
5. Administrator runs self-healing:
   ```bash
   ./vaultfs-ctl heal /tmp/vaultfs_backing
   ```
6. **Result:** All encrypted ciphertext blocks are ejected, and original data is 100% restored with **identical SHA-256 hashes**.

---

## 6. Patent Novelty & Academic Claims

For patent evaluation and academic defense, VaultFS introduces three core claims:

1. **Claim 1 (Autonomous Quarantine Tomb):** A content-addressed storage architecture wherein pre-overwrite block pointers are preserved in an isolated ghost tomb structure upon detection of anomalous write characteristics, guaranteeing zero-data-loss rollback without requiring prior user-scheduled snapshots.
2. **Claim 2 (Statistical Inode-Entropy Interception):** An in-line VFS write filter calculating running Shannon entropy per inode to detect unauthorized payload encryption at write time, neutralizing ransomware before persistent storage mutation occurs.
3. **Claim 3 (Convergent Cryptographic Deduplication):** A deterministic chunk initialization vector scheme deriving IVs from chunk hash and user master key, enabling globally deduplicated storage across snapshots and files while preserving full AES-256 confidentiality against untrusted backing stores.

---

## 7. Directory Structure

```
VaultFS/
├── Makefile                # Multi-target build rules with fuse3 and OpenSSL
├── Dockerfile              # Ubuntu container with FUSE 3 & crypto headers
├── run.sh                  # One-click runner for macOS & Linux
├── test_demos.sh           # Automated 5-stage core demonstration suite
├── test_ransomware.sh      # Automated RansomShield attack & self-healing test
├── README.md               # Architecture and user guide
├── REPORT.md               # Academic syllabus mapping & patent claims report
├── src/
│   ├── vaultfs.h           # Data structures, constants, and system types
│   ├── main.c              # CLI parsing and FUSE lifecycle loop
│   ├── storage.h / .c      # Content-addressed chunking, refcounts, and disk catalog
│   ├── crypto.h / .c       # Convergent AES-256 encryption, PBKDF2, SHA-256
│   ├── entropy.h / .c      # Shannon entropy calculation & anomaly detection
│   ├── inode.h / .c        # Inode table, path resolution, ghost block quarantine
│   ├── snapshot.h / .c     # Copy-On-Write snapshot engine and historical views
│   └── fuse_ops.h / .c     # FUSE 3 filesystem operation callbacks
└── tools/
    └── vaultfs_ctl.c       # Analytics dashboard, block inspector & self-healing CLI
```
