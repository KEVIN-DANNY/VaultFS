#include "wal.h"
#include "storage.h"
#include "inode.h"

static int             s_wal_fd = -1;
static char            s_wal_path[VAULTFS_MAX_PATH + 64];
static uint64_t        s_next_txid = 1;
static pthread_mutex_t s_wal_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t calculate_checksum(const WALRecord *rec) {
    const unsigned char *p = (const unsigned char *)rec;
    size_t len = sizeof(WALRecord) - sizeof(uint32_t); // Exclude checksum field
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= 16777619u;
    }
    return hash;
}

int wal_init(const char *backing_dir) {
    pthread_mutex_lock(&s_wal_lock);
    snprintf(s_wal_path, sizeof(s_wal_path), "%s/metadata/wal.log", backing_dir);

    s_wal_fd = open(s_wal_path, O_RDWR | O_CREAT, 0644);
    if (s_wal_fd < 0) {
        pthread_mutex_unlock(&s_wal_lock);
        return -errno;
    }

    // Determine highest existing txid
    off_t size = lseek(s_wal_fd, 0, SEEK_END);
    if (size >= (off_t)sizeof(WALRecord)) {
        size_t count = size / sizeof(WALRecord);
        lseek(s_wal_fd, (off_t)((count - 1) * sizeof(WALRecord)), SEEK_SET);
        WALRecord last_rec;
        if (read(s_wal_fd, &last_rec, sizeof(WALRecord)) == sizeof(WALRecord)) {
            if (last_rec.magic == WAL_MAGIC && last_rec.txid >= s_next_txid) {
                s_next_txid = last_rec.txid + 1;
            }
        }
        lseek(s_wal_fd, 0, SEEK_END);
    }

    pthread_mutex_unlock(&s_wal_lock);
    return 0;
}

void wal_close(void) {
    pthread_mutex_lock(&s_wal_lock);
    if (s_wal_fd >= 0) {
        fdatasync(s_wal_fd);
        close(s_wal_fd);
        s_wal_fd = -1;
    }
    pthread_mutex_unlock(&s_wal_lock);
}

uint64_t wal_begin_tx(void) {
    pthread_mutex_lock(&s_wal_lock);
    uint64_t txid = s_next_txid++;
    pthread_mutex_unlock(&s_wal_lock);
    return txid;
}

int wal_sync(void) {
    if (s_wal_fd >= 0) {
        return fdatasync(s_wal_fd);
    }
    return 0;
}

int wal_log_pre_overwrite(uint64_t txid, uint64_t ino, uint32_t chunk_idx,
                           const char *old_hash, const char *new_hash,
                           uint64_t old_size, uint64_t new_size) {
    pthread_mutex_lock(&s_wal_lock);
    if (s_wal_fd < 0) {
        pthread_mutex_unlock(&s_wal_lock);
        return -EBADF;
    }

    // Pin the pre-image chunk in storage engine so garbage collection cannot delete it
    if (old_hash && strlen(old_hash) > 0) {
        storage_pin_chunk(old_hash);
    }

    WALRecord rec;
    memset(&rec, 0, sizeof(WALRecord));
    rec.magic = WAL_MAGIC;
    rec.op_type = WAL_OP_PRE_OVERWRITE;
    rec.txid = txid;
    rec.ino = ino;
    rec.chunk_idx = chunk_idx;
    if (old_hash) strncpy(rec.old_hash, old_hash, VAULTFS_HASH_HEX_LEN);
    if (new_hash) strncpy(rec.new_hash, new_hash, VAULTFS_HASH_HEX_LEN);
    rec.old_size = old_size;
    rec.new_size = new_size;
    rec.timestamp = time(NULL);
    rec.checksum = calculate_checksum(&rec);

    ssize_t w = write(s_wal_fd, &rec, sizeof(WALRecord));
    if (w != sizeof(WALRecord)) {
        pthread_mutex_unlock(&s_wal_lock);
        return -EIO;
    }

    fdatasync(s_wal_fd);
    pthread_mutex_unlock(&s_wal_lock);

    fault_inject_point("after_log");
    fault_inject_point("after_wal_write");
    return 0;
}

int wal_log_pre_truncate(uint64_t txid, uint64_t ino, uint32_t chunk_idx,
                          const char *old_hash, uint64_t old_size, uint64_t new_size) {
    pthread_mutex_lock(&s_wal_lock);
    if (s_wal_fd < 0) {
        pthread_mutex_unlock(&s_wal_lock);
        return -EBADF;
    }

    // Pin the pre-image chunk
    if (old_hash && strlen(old_hash) > 0) {
        storage_pin_chunk(old_hash);
    }

    WALRecord rec;
    memset(&rec, 0, sizeof(WALRecord));
    rec.magic = WAL_MAGIC;
    rec.op_type = WAL_OP_PRE_TRUNCATE;
    rec.txid = txid;
    rec.ino = ino;
    rec.chunk_idx = chunk_idx;
    if (old_hash) strncpy(rec.old_hash, old_hash, VAULTFS_HASH_HEX_LEN);
    rec.old_size = old_size;
    rec.new_size = new_size;
    rec.timestamp = time(NULL);
    rec.checksum = calculate_checksum(&rec);

    ssize_t w = write(s_wal_fd, &rec, sizeof(WALRecord));
    if (w != sizeof(WALRecord)) {
        pthread_mutex_unlock(&s_wal_lock);
        return -EIO;
    }

    fdatasync(s_wal_fd);
    pthread_mutex_unlock(&s_wal_lock);

    fault_inject_point("after_log");
    fault_inject_point("during_truncate");
    return 0;
}

int wal_commit_tx(uint64_t txid) {
    pthread_mutex_lock(&s_wal_lock);
    if (s_wal_fd < 0) {
        pthread_mutex_unlock(&s_wal_lock);
        return -EBADF;
    }

    WALRecord rec;
    memset(&rec, 0, sizeof(WALRecord));
    rec.magic = WAL_MAGIC;
    rec.op_type = WAL_OP_COMMIT;
    rec.txid = txid;
    rec.timestamp = time(NULL);
    rec.checksum = calculate_checksum(&rec);

    ssize_t w = write(s_wal_fd, &rec, sizeof(WALRecord));
    if (w != sizeof(WALRecord)) {
        pthread_mutex_unlock(&s_wal_lock);
        return -EIO;
    }

    fdatasync(s_wal_fd);
    pthread_mutex_unlock(&s_wal_lock);
    return 0;
}

static void wal_checkpoint_locked(void) {
    if (s_wal_fd >= 0) {
        close(s_wal_fd);
        // Truncate WAL to clean empty file
        s_wal_fd = open(s_wal_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    }
}

int wal_checkpoint(void) {
    pthread_mutex_lock(&s_wal_lock);
    wal_checkpoint_locked();
    pthread_mutex_unlock(&s_wal_lock);
    return 0;
}

void fault_inject_point(const char *point_name) {
    if (!point_name) return;
    const char *target = getenv("VAULTFS_CRASH_AT");
    if (!target || strlen(target) == 0) return;

    if (strstr(target, point_name) != NULL) {
        static int crash_hit = 0;
        crash_hit++;
        const char *count_str = getenv("VAULTFS_CRASH_COUNT");
        int target_count = count_str ? atoi(count_str) : 1;
        if (target_count <= 0) target_count = 1;

        if (crash_hit >= target_count) {
            fprintf(stderr, "\n=======================================================================\n");
            fprintf(stderr, "[FAULT INJECTION] Simulated crash triggered at point '%s' (hit %d)\n",
                    point_name, crash_hit);
            fprintf(stderr, "=======================================================================\n\n");
            fflush(stderr);
            abort();
        }
    }
}

int wal_recover_and_replay(void) {
    pthread_mutex_lock(&s_wal_lock);
    if (s_wal_fd < 0) {
        pthread_mutex_unlock(&s_wal_lock);
        return 0;
    }

    off_t size = lseek(s_wal_fd, 0, SEEK_END);
    if (size < (off_t)sizeof(WALRecord)) {
        pthread_mutex_unlock(&s_wal_lock);
        return 0;
    }

    size_t num_records = size / sizeof(WALRecord);
    lseek(s_wal_fd, 0, SEEK_SET);

    WALRecord *records = calloc(num_records, sizeof(WALRecord));
    if (!records) {
        pthread_mutex_unlock(&s_wal_lock);
        return -ENOMEM;
    }

    ssize_t rd = read(s_wal_fd, records, num_records * sizeof(WALRecord));
    if (rd < 0) {
        free(records);
        pthread_mutex_unlock(&s_wal_lock);
        return -EIO;
    }
    num_records = rd / sizeof(WALRecord);

    // Pass 1: Identify all committed transaction IDs
    #define MAX_TX_TRACK 16384
    uint64_t committed_txids[MAX_TX_TRACK];
    size_t num_committed = 0;

    for (size_t i = 0; i < num_records; i++) {
        if (records[i].magic != WAL_MAGIC) continue;
        if (records[i].checksum != calculate_checksum(&records[i])) continue;

        if (records[i].op_type == WAL_OP_COMMIT) {
            if (num_committed < MAX_TX_TRACK) {
                committed_txids[num_committed++] = records[i].txid;
            }
        }
    }

    // Pass 2: Inspect uncommitted transactions and roll back inconsistent state
    int recovered_txs = 0;
    int rollbacks_applied = 0;

    for (size_t i = 0; i < num_records; i++) {
        if (records[i].magic != WAL_MAGIC) continue;
        if (records[i].checksum != calculate_checksum(&records[i])) continue;

        if (records[i].op_type == WAL_OP_PRE_OVERWRITE || records[i].op_type == WAL_OP_PRE_TRUNCATE) {
            bool is_committed = false;
            for (size_t c = 0; c < num_committed; c++) {
                if (committed_txids[c] == records[i].txid) {
                    is_committed = true;
                    break;
                }
            }

            if (!is_committed) {
                // Uncommitted transaction: roll back inode mapping to pre-image
                VaultInode *node = inode_get_by_id(records[i].ino);
                if (node) {
                    if (records[i].chunk_idx < VAULTFS_MAX_CHUNKS) {
                        if (strcmp(node->chunk_hashes[records[i].chunk_idx], records[i].old_hash) != 0) {
                            fprintf(stderr, "[WAL RECOVERY] Rolling back uncommitted chunk %u on inode %lu ('%s') to pre-image %s\n",
                                    records[i].chunk_idx, records[i].ino, node->name, records[i].old_hash);
                            strcpy(node->chunk_hashes[records[i].chunk_idx], records[i].old_hash);
                            rollbacks_applied++;
                        }
                        if (records[i].chunk_idx >= node->chunk_count && strlen(records[i].old_hash) > 0) {
                            node->chunk_count = records[i].chunk_idx + 1;
                        }
                    }
                    if (records[i].old_size > 0 && node->size != records[i].old_size) {
                        node->size = records[i].old_size;
                    }
                }
                recovered_txs++;
            }
        }
    }

    free(records);

    if (rollbacks_applied > 0) {
        inode_save();
    }

    // Checkpoint clean log while holding lock
    wal_checkpoint_locked();

    pthread_mutex_unlock(&s_wal_lock);

    // Pass 3: Rebuild and audit storage catalog refcounts across all valid inodes and snapshots
    storage_rebuild_and_audit();

    return recovered_txs;
}
