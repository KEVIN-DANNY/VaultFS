#ifndef VAULTFS_H
#define VAULTFS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define VAULTFS_MAGIC           0x5641554C  // "VAUL"
#define VAULTFS_VERSION         2           // V2 with RansomShield
#define VAULTFS_BLOCK_SIZE      4096        // 4 KB Content-Addressed Chunk Size
#define VAULTFS_HASH_LEN        32          // SHA-256 byte length
#define VAULTFS_HASH_HEX_LEN    64          // SHA-256 hex string length
#define VAULTFS_MAX_PATH        2048
#define VAULTFS_MAX_NAME        256
#define VAULTFS_MAX_INODES      8192
#define VAULTFS_MAX_CHUNKS      16384       // Max file size = 16384 * 4KB = 64 MB
#define VAULTFS_MAX_SNAPSHOTS   128

// Inode Structure with RansomShield Ghost-Block Quarantine Tomb
typedef struct {
    uint64_t ino;
    uint64_t parent_ino;
    char     name[VAULTFS_MAX_NAME];
    mode_t   mode;              // S_IFDIR, S_IFREG, permissions
    uid_t    uid;
    gid_t    gid;
    uint64_t size;              // File size in bytes
    time_t   atime;
    time_t   mtime;
    time_t   ctime;
    uint32_t chunk_count;
    char     chunk_hashes[VAULTFS_MAX_CHUNKS][VAULTFS_HASH_HEX_LEN + 1];

    // --- RansomShield Protection Metadata ---
    bool     is_quarantined;
    double   baseline_entropy;
    uint64_t ghost_size;
    uint32_t ghost_chunk_count;
    char     ghost_chunk_hashes[VAULTFS_MAX_CHUNKS][VAULTFS_HASH_HEX_LEN + 1];
    pid_t    quarantined_by_tree;   // Process-tree root PID that triggered quarantine (Feature 1)
} VaultInode;

// Snapshot Structure
typedef struct {
    char        name[VAULTFS_MAX_NAME];
    time_t      created_at;
    uint32_t    inode_count;
    VaultInode *inodes;
} VaultSnapshot;

// Filesystem Statistics
typedef struct {
    uint64_t total_files;
    uint64_t total_dirs;
    uint64_t logical_bytes;
    uint64_t physical_bytes;
    uint64_t unique_blocks;
    uint64_t total_chunks_referenced;
    uint32_t snapshot_count;
    double   dedup_ratio;
    double   space_saved_percent;

    // RansomShield stats
    uint32_t ransomware_attacks_detected;
    uint32_t files_quarantined;
} VaultFSStats;

typedef enum {
    SCORING_MODE_DEDUP_AWARE = 0,
    SCORING_MODE_ENTROPY_ONLY = 1
} ScoringMode;

typedef struct {
    ScoringMode mode;
    double      threshold;            // Combined anomaly score threshold (default: 0.50)
    double      weight_entropy_jump;  // Weight for baseline entropy surge (default: 0.35)
    double      weight_abs_entropy;   // Weight for absolute high entropy (default: 0.25)
    double      weight_dedup_novelty; // Weight for dedup novelty 1 - hit_ratio (default: 0.20)
    double      weight_replacement;   // Weight for in-place replacement fraction (default: 0.20)
} RansomShieldConfig;

// Global Filesystem State
typedef struct {
    char          backing_dir[VAULTFS_MAX_PATH];
    char          mount_point[VAULTFS_MAX_PATH];
    char          password[256];
    unsigned char master_key[32];   // 256-bit AES key
    bool          encrypted;
    bool          debug;
    pthread_mutex_t lock;

    // Active Inode Table
    VaultInode   *inodes;
    uint32_t      inode_count;
    uint64_t      next_ino;

    // Snapshots
    VaultSnapshot snapshots[VAULTFS_MAX_SNAPSHOTS];
    uint32_t      snapshot_count;

    // RansomShield Engine
    bool               ransomshield_enabled;
    RansomShieldConfig rs_config;
    uint32_t           ransomware_attacks_detected;
    uint32_t           files_quarantined;
} VaultFSContext;

extern VaultFSContext g_vaultfs;

#endif // VAULTFS_H
