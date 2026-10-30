#ifndef VAULTFS_WAL_H
#define VAULTFS_WAL_H

#include "vaultfs.h"

#define WAL_MAGIC   0x57414C31  // "WAL1"
#define WAL_VERSION 1

typedef enum {
    WAL_OP_PRE_OVERWRITE   = 1, // Pre-image block pinned before write/overwrite
    WAL_OP_PRE_TRUNCATE    = 2, // Pre-image blocks pinned before truncate
    WAL_OP_COMMIT          = 3, // Transaction committed durably
    WAL_OP_ABORT           = 4, // Transaction aborted
    WAL_OP_CHECKPOINT      = 5  // Checkpoint marker
} WALOpType;

// On-disk binary record for intent logging and crash consistency
typedef struct {
    uint32_t magic;
    uint32_t op_type;
    uint64_t txid;
    uint64_t ino;
    uint32_t chunk_idx;
    char     old_hash[VAULTFS_HASH_HEX_LEN + 1];
    char     new_hash[VAULTFS_HASH_HEX_LEN + 1];
    uint64_t old_size;
    uint64_t new_size;
    time_t   timestamp;
    uint32_t checksum;
} WALRecord;

/**
 * Initialize write-ahead logging subsystem.
 */
int  wal_init(const char *backing_dir);

/**
 * Close and sync write-ahead logging subsystem.
 */
void wal_close(void);

/**
 * Allocate a new monotonically increasing transaction ID.
 */
uint64_t wal_begin_tx(void);

/**
 * Log pre-image intent before an overwrite or block replacement occurs.
 * Pins the old block in the catalog and fsyncs the log to disk.
 */
int  wal_log_pre_overwrite(uint64_t txid, uint64_t ino, uint32_t chunk_idx,
                           const char *old_hash, const char *new_hash,
                           uint64_t old_size, uint64_t new_size);

/**
 * Log pre-image intent before a truncate occurs.
 * Pins all truncated blocks and fsyncs the log to disk.
 */
int  wal_log_pre_truncate(uint64_t txid, uint64_t ino, uint32_t chunk_idx,
                          const char *old_hash, uint64_t old_size, uint64_t new_size);

/**
 * Commit a transaction in the log and fsync it.
 */
int  wal_commit_tx(uint64_t txid);

/**
 * Flush and fsync the WAL file.
 */
int  wal_sync(void);

/**
 * Mount-time recovery: scans wal.log, rolls back uncommitted transactions,
 * restores pinned pre-images, and cleans up inconsistent state.
 */
int  wal_recover_and_replay(void);

/**
 * Clear or checkpoint the WAL after full consistency verification.
 */
int  wal_checkpoint(void);

/**
 * Fault injection helper: checks VAULTFS_CRASH_AT env var and aborts if matched.
 */
void fault_inject_point(const char *point_name);

#endif // VAULTFS_WAL_H
