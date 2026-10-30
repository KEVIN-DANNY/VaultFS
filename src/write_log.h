#ifndef VAULTFS_WRITE_LOG_H
#define VAULTFS_WRITE_LOG_H

#include "vaultfs.h"

#define WRITE_LOG_CAPACITY   32768
#define MAX_TRACKED_TREES    256
#define ANOMALY_WINDOW_SEC   60
#define ANOMALY_DEFAULT_THRESHOLD 1.0

typedef struct {
    uint64_t ino;
    off_t    offset;
    size_t   len;
    pid_t    pid;
    pid_t    tree_root;
    time_t   timestamp;
    double   entropy;
    double   dedup_hit_ratio;
} WriteLogEntry;

typedef struct {
    pid_t    tree_root;
    double   anomaly_score;
    time_t   first_seen;
    time_t   last_seen;
    bool     is_flagged;
    uint32_t modified_count;
    uint64_t modified_inodes[256];
} TreeAnomalyRecord;

typedef struct {
    pid_t    tree_root;
    double   anomaly_score;
    time_t   flagged_at;
    uint32_t file_count;
    char     file_names[32][VAULTFS_MAX_NAME];
    uint64_t inode_ids[32];
} SuspectDiskRecord;

void write_log_init(const char *backing_dir);
void write_log_append(uint64_t ino, off_t offset, size_t len,
                      pid_t pid, pid_t tree_root,
                      double entropy, double dedup_hit_ratio);

/**
 * Updates the sliding-window anomaly score for a process tree.
 * Returns true if the process tree crosses the threshold.
 */
bool write_log_evaluate_tree(pid_t tree_root, uint64_t ino, double anomaly_delta, double threshold);

bool write_log_is_tree_flagged(pid_t tree_root);
int  write_log_get_tree_inodes(pid_t tree_root, uint64_t *out_inodes, int max_inodes);
void write_log_record_quarantined_file(pid_t tree_root, uint64_t ino, const char *filename, double score);
void write_log_sync_suspects(void);

#endif // VAULTFS_WRITE_LOG_H
