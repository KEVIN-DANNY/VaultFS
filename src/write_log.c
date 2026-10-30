#include "write_log.h"
#include "inode.h"

static WriteLogEntry     s_ring_buffer[WRITE_LOG_CAPACITY];
static size_t            s_ring_head = 0;
static size_t            s_ring_count = 0;
static pthread_mutex_t   s_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static TreeAnomalyRecord s_trees[MAX_TRACKED_TREES];
static size_t            s_tree_count = 0;

static char              s_backing_dir[VAULTFS_MAX_PATH];
static char              s_suspects_path[VAULTFS_MAX_PATH + 64];

void write_log_init(const char *backing_dir) {
    pthread_mutex_lock(&s_log_mutex);
    if (backing_dir) {
        strncpy(s_backing_dir, backing_dir, sizeof(s_backing_dir) - 1);
        snprintf(s_suspects_path, sizeof(s_suspects_path), "%s/metadata/suspects.dat", backing_dir);
    }
    s_ring_head = 0;
    s_ring_count = 0;
    s_tree_count = 0;
    memset(s_ring_buffer, 0, sizeof(s_ring_buffer));
    memset(s_trees, 0, sizeof(s_trees));
    pthread_mutex_unlock(&s_log_mutex);
}

void write_log_append(uint64_t ino, off_t offset, size_t len,
                      pid_t pid, pid_t tree_root,
                      double entropy, double dedup_hit_ratio) {
    pthread_mutex_lock(&s_log_mutex);

    size_t idx = s_ring_head;
    s_ring_buffer[idx].ino = ino;
    s_ring_buffer[idx].offset = offset;
    s_ring_buffer[idx].len = len;
    s_ring_buffer[idx].pid = pid;
    s_ring_buffer[idx].tree_root = tree_root;
    s_ring_buffer[idx].timestamp = time(NULL);
    s_ring_buffer[idx].entropy = entropy;
    s_ring_buffer[idx].dedup_hit_ratio = dedup_hit_ratio;

    s_ring_head = (s_ring_head + 1) % WRITE_LOG_CAPACITY;
    if (s_ring_count < WRITE_LOG_CAPACITY) {
        s_ring_count++;
    }

    pthread_mutex_unlock(&s_log_mutex);
}

static TreeAnomalyRecord *find_or_create_tree(pid_t tree_root, time_t now) {
    for (size_t i = 0; i < s_tree_count; i++) {
        if (s_trees[i].tree_root == tree_root) {
            return &s_trees[i];
        }
    }

    if (s_tree_count < MAX_TRACKED_TREES) {
        TreeAnomalyRecord *t = &s_trees[s_tree_count++];
        memset(t, 0, sizeof(TreeAnomalyRecord));
        t->tree_root = tree_root;
        t->first_seen = now;
        t->last_seen = now;
        return t;
    }

    // Evict oldest unflagged tree
    size_t oldest_idx = 0;
    time_t oldest_time = now;
    for (size_t i = 0; i < s_tree_count; i++) {
        if (!s_trees[i].is_flagged && s_trees[i].last_seen < oldest_time) {
            oldest_time = s_trees[i].last_seen;
            oldest_idx = i;
        }
    }
    TreeAnomalyRecord *t = &s_trees[oldest_idx];
    memset(t, 0, sizeof(TreeAnomalyRecord));
    t->tree_root = tree_root;
    t->first_seen = now;
    t->last_seen = now;
    return t;
}

bool write_log_evaluate_tree(pid_t tree_root, uint64_t ino, double anomaly_delta, double threshold) {
    pthread_mutex_lock(&s_log_mutex);
    time_t now = time(NULL);

    TreeAnomalyRecord *tree = find_or_create_tree(tree_root, now);

    // Sliding window check: decay old score if outside window
    if ((now - tree->last_seen) > ANOMALY_WINDOW_SEC) {
        tree->anomaly_score = 0.0;
        tree->first_seen = now;
    }

    tree->last_seen = now;
    tree->anomaly_score += anomaly_delta;

    // Track modified inode
    bool already_tracked = false;
    for (uint32_t i = 0; i < tree->modified_count; i++) {
        if (tree->modified_inodes[i] == ino) {
            already_tracked = true;
            break;
        }
    }
    if (!already_tracked && tree->modified_count < 256) {
        tree->modified_inodes[tree->modified_count++] = ino;
    }

    bool newly_flagged = false;
    if (tree->anomaly_score >= threshold && !tree->is_flagged) {
        tree->is_flagged = true;
        newly_flagged = true;
    }

    pthread_mutex_unlock(&s_log_mutex);
    return newly_flagged || tree->is_flagged;
}

bool write_log_is_tree_flagged(pid_t tree_root) {
    pthread_mutex_lock(&s_log_mutex);
    for (size_t i = 0; i < s_tree_count; i++) {
        if (s_trees[i].tree_root == tree_root) {
            bool flagged = s_trees[i].is_flagged;
            pthread_mutex_unlock(&s_log_mutex);
            return flagged;
        }
    }
    pthread_mutex_unlock(&s_log_mutex);
    return false;
}

int write_log_get_tree_inodes(pid_t tree_root, uint64_t *out_inodes, int max_inodes) {
    pthread_mutex_lock(&s_log_mutex);
    for (size_t i = 0; i < s_tree_count; i++) {
        if (s_trees[i].tree_root == tree_root) {
            int count = (int)s_trees[i].modified_count;
            if (count > max_inodes) count = max_inodes;
            for (int j = 0; j < count; j++) {
                out_inodes[j] = s_trees[i].modified_inodes[j];
            }
            pthread_mutex_unlock(&s_log_mutex);
            return count;
        }
    }
    pthread_mutex_unlock(&s_log_mutex);
    return 0;
}

void write_log_record_quarantined_file(pid_t tree_root, uint64_t ino, const char *filename, double score) {
    pthread_mutex_lock(&s_log_mutex);
    if (strlen(s_suspects_path) == 0) {
        pthread_mutex_unlock(&s_log_mutex);
        return;
    }

    // Load existing suspects or append
    SuspectDiskRecord records[MAX_TRACKED_TREES];
    uint32_t count = 0;

    FILE *f = fopen(s_suspects_path, "rb");
    if (f) {
        if (fread(&count, sizeof(uint32_t), 1, f) == 1 && count <= MAX_TRACKED_TREES) {
            size_t rd = fread(records, sizeof(SuspectDiskRecord), count, f);
            (void)rd;
        } else {
            count = 0;
        }
        fclose(f);
    }

    int found_idx = -1;
    for (uint32_t i = 0; i < count; i++) {
        if (records[i].tree_root == tree_root) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0) {
        if (count < MAX_TRACKED_TREES) {
            found_idx = (int)count++;
            memset(&records[found_idx], 0, sizeof(SuspectDiskRecord));
            records[found_idx].tree_root = tree_root;
            records[found_idx].flagged_at = time(NULL);
        } else {
            pthread_mutex_unlock(&s_log_mutex);
            return;
        }
    }

    records[found_idx].anomaly_score = score;
    bool already_has_file = false;
    for (uint32_t j = 0; j < records[found_idx].file_count; j++) {
        if (records[found_idx].inode_ids[j] == ino) {
            already_has_file = true;
            break;
        }
    }

    if (!already_has_file && records[found_idx].file_count < 32) {
        uint32_t fc = records[found_idx].file_count;
        records[found_idx].inode_ids[fc] = ino;
        if (filename) {
            strncpy(records[found_idx].file_names[fc], filename, VAULTFS_MAX_NAME - 1);
        }
        records[found_idx].file_count++;
    }

    // Save atomically via .tmp
    char tmp_path[VAULTFS_MAX_PATH + 128];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", s_suspects_path);
    FILE *fo = fopen(tmp_path, "wb");
    if (fo) {
        fwrite(&count, sizeof(uint32_t), 1, fo);
        fwrite(records, sizeof(SuspectDiskRecord), count, fo);
        fflush(fo);
        fdatasync(fileno(fo));
        fclose(fo);
        rename(tmp_path, s_suspects_path);
    }

    pthread_mutex_unlock(&s_log_mutex);
}

void write_log_sync_suspects(void) {
    // Placeholder for any periodic flushing
}
