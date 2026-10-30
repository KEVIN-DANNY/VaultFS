#include "inode.h"
#include "storage.h"
#include "entropy.h"
#include "wal.h"

static void split_path(const char *path, char *parent_path, char *basename) {
    char temp[VAULTFS_MAX_PATH];
    strncpy(temp, path, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char *last_slash = strrchr(temp, '/');
    if (!last_slash) {
        strcpy(parent_path, "/");
        strcpy(basename, path);
        return;
    }

    if (last_slash == temp) {
        // Path is in root directory, e.g. "/file.txt"
        strcpy(parent_path, "/");
        strcpy(basename, last_slash + 1);
    } else {
        *last_slash = '\0';
        strcpy(parent_path, temp);
        strcpy(basename, last_slash + 1);
    }
}

int inode_init(void) {
    g_vaultfs.inodes = calloc(VAULTFS_MAX_INODES, sizeof(VaultInode));
    if (!g_vaultfs.inodes) return -ENOMEM;

    g_vaultfs.inode_count = 0;
    g_vaultfs.next_ino = 1;
    g_vaultfs.ransomshield_enabled = true;

    inode_load();

    if (g_vaultfs.inode_count == 0) {
        // Create root directory inode (ino = 1)
        VaultInode *root = &g_vaultfs.inodes[0];
        root->ino = 1;
        root->parent_ino = 1;
        strcpy(root->name, "/");
        root->mode = S_IFDIR | 0755;
        root->uid = getuid();
        root->gid = getgid();
        root->size = 4096;
        root->atime = root->mtime = root->ctime = time(NULL);
        root->chunk_count = 0;
        root->baseline_entropy = 0.0;
        root->is_quarantined = false;

        g_vaultfs.inode_count = 1;
        g_vaultfs.next_ino = 2;
        inode_save();
    }
    return 0;
}

VaultInode *inode_get_by_id(uint64_t ino) {
    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        if (g_vaultfs.inodes[i].ino == ino) {
            return &g_vaultfs.inodes[i];
        }
    }
    return NULL;
}

VaultInode *inode_lookup(const char *path) {
    if (!path || strlen(path) == 0) return NULL;
    if (strcmp(path, "/") == 0) return inode_get_by_id(1);

    // Normalize path by skipping leading '/'
    const char *p = path;
    if (*p == '/') p++;

    char path_copy[VAULTFS_MAX_PATH];
    strncpy(path_copy, p, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    uint64_t current_ino = 1; // start at root
    char *token = strtok(path_copy, "/");

    while (token) {
        bool found = false;
        for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
            VaultInode *node = &g_vaultfs.inodes[i];
            if (node->parent_ino == current_ino && strcmp(node->name, token) == 0) {
                current_ino = node->ino;
                found = true;
                break;
            }
        }
        if (!found) return NULL;
        token = strtok(NULL, "/");
    }

    return inode_get_by_id(current_ino);
}

int inode_create(const char *path, mode_t mode, VaultInode **out_node) {
    if (inode_lookup(path) != NULL) {
        return -EEXIST;
    }

    char parent_path[VAULTFS_MAX_PATH];
    char name[VAULTFS_MAX_NAME];
    split_path(path, parent_path, name);

    VaultInode *parent = inode_lookup(parent_path);
    if (!parent) return -ENOENT;
    if (!S_ISDIR(parent->mode)) return -ENOTDIR;

    if (g_vaultfs.inode_count >= VAULTFS_MAX_INODES) {
        return -ENOSPC;
    }

    VaultInode *node = &g_vaultfs.inodes[g_vaultfs.inode_count];
    memset(node, 0, sizeof(VaultInode));

    node->ino = g_vaultfs.next_ino++;
    node->parent_ino = parent->ino;
    strncpy(node->name, name, VAULTFS_MAX_NAME - 1);
    node->mode = mode;
    node->uid = getuid();
    node->gid = getgid();
    node->size = S_ISDIR(mode) ? 4096 : 0;
    node->atime = node->mtime = node->ctime = time(NULL);
    node->chunk_count = 0;
    node->baseline_entropy = 0.0;
    node->is_quarantined = false;

    g_vaultfs.inode_count++;

    parent->mtime = time(NULL);
    inode_save();

    if (out_node) *out_node = node;
    return 0;
}

int inode_write(VaultInode *node, const char *buf, size_t size, off_t offset) {
    if (!node || S_ISDIR(node->mode)) return -EISDIR;
    if (size == 0) return 0;

    // --- RansomShield Anomaly Detection Pipeline ---
    if (g_vaultfs.ransomshield_enabled && node->baseline_entropy > 0.0) {
        double incoming_entropy = entropy_calculate((const unsigned char *)buf, size);

        if (entropy_is_ransomware_suspect(node->baseline_entropy, incoming_entropy)) {
            if (!node->is_quarantined) {
                node->is_quarantined = true;
                if (node->ghost_chunk_count == 0 && node->chunk_count > 0) {
                    node->ghost_size = node->size;
                    node->ghost_chunk_count = node->chunk_count;
                    for (uint32_t c = 0; c < node->chunk_count; c++) {
                        strcpy(node->ghost_chunk_hashes[c], node->chunk_hashes[c]);
                        storage_retain_chunk(node->ghost_chunk_hashes[c]);
                    }
                }

                g_vaultfs.ransomware_attacks_detected++;
                g_vaultfs.files_quarantined++;

                fprintf(stderr, "\n[!] ==================================================================\n");
                fprintf(stderr, "[!] [RANSOMSHIELD ALERT] Ransomware attack intercepted on file '%s'!\n", node->name);
                fprintf(stderr, "[!] Baseline Entropy: %.2f | Incoming Entropy: %.2f (Elevated)\n",
                        node->baseline_entropy, incoming_entropy);
                fprintf(stderr, "[!] Original %u block(s) frozen in Cryptographic Quarantine Tomb.\n", node->ghost_chunk_count);
                fprintf(stderr, "[!] Self-healing available via: vaultfs-ctl heal <storage_dir>\n");
                fprintf(stderr, "[!] ==================================================================\n\n");
            }
        } else if (node->ghost_chunk_count > 0 && !node->is_quarantined && incoming_entropy < 6.8) {
            // Normal low-entropy write over truncated file: safe to release ghost blocks
            for (uint32_t c = 0; c < node->ghost_chunk_count; c++) {
                storage_release_chunk(node->ghost_chunk_hashes[c]);
            }
            node->ghost_chunk_count = 0;
            node->ghost_size = 0;
        }
    }

    size_t bytes_written = 0;

    while (bytes_written < size) {
        off_t current_pos = offset + bytes_written;
        size_t chunk_idx = current_pos / VAULTFS_BLOCK_SIZE;
        size_t chunk_offset = current_pos % VAULTFS_BLOCK_SIZE;
        size_t write_len = VAULTFS_BLOCK_SIZE - chunk_offset;
        if (write_len > (size - bytes_written)) {
            write_len = size - bytes_written;
        }

        if (chunk_idx >= VAULTFS_MAX_CHUNKS) {
            return -EFBIG;
        }

        unsigned char chunk_buf[VAULTFS_BLOCK_SIZE];
        memset(chunk_buf, 0, sizeof(chunk_buf));

        char old_hash[VAULTFS_HASH_HEX_LEN + 1];
        old_hash[0] = '\0';

        // If partial chunk write, read existing chunk data first
        if (chunk_idx < node->chunk_count) {
            strcpy(old_hash, node->chunk_hashes[chunk_idx]);
            if (chunk_offset > 0 || write_len < VAULTFS_BLOCK_SIZE) {
                fault_inject_point("during_partial_write");
                size_t actual_len = 0;
                storage_read_chunk(old_hash, chunk_buf, &actual_len);
            }
        }

        // Apply new data into chunk buffer
        memcpy(chunk_buf + chunk_offset, buf + bytes_written, write_len);

        // Calculate chunk data length
        size_t current_chunk_len = chunk_offset + write_len;
        if (chunk_idx < node->chunk_count) {
            size_t remaining_in_file = node->size - (chunk_idx * VAULTFS_BLOCK_SIZE);
            if (remaining_in_file > current_chunk_len && remaining_in_file <= VAULTFS_BLOCK_SIZE) {
                current_chunk_len = remaining_in_file;
            }
        }

        // Write chunk through Deduplication & Convergent Encryption
        char new_hash[VAULTFS_HASH_HEX_LEN + 1];
        if (storage_write_chunk(chunk_buf, current_chunk_len, new_hash) != 0) {
            return -EIO;
        }

        // Feature 3: Write-Ahead Intent Logging & Crash-Consistent Pre-image Pinning
        uint64_t txid = wal_begin_tx();
        uint64_t projected_size = (offset + size > node->size) ? (offset + size) : node->size;
        if (strlen(old_hash) > 0) {
            wal_log_pre_overwrite(txid, node->ino, (uint32_t)chunk_idx, old_hash, new_hash, node->size, projected_size);
        }

        fault_inject_point("before_inode_update");

        // Update node chunk hash table
        if (chunk_idx < node->chunk_count) {
            strcpy(node->chunk_hashes[chunk_idx], new_hash);
        } else {
            while (node->chunk_count < chunk_idx) {
                char zero_hash[VAULTFS_HASH_HEX_LEN + 1];
                unsigned char zero_buf[VAULTFS_BLOCK_SIZE] = {0};
                storage_write_chunk(zero_buf, VAULTFS_BLOCK_SIZE, zero_hash);
                strcpy(node->chunk_hashes[node->chunk_count++], zero_hash);
            }
            strcpy(node->chunk_hashes[node->chunk_count++], new_hash);
        }

        fault_inject_point("after_inode_update");

        // Commit WAL transaction
        wal_commit_tx(txid);

        // Safely unpin and release old chunk
        if (strlen(old_hash) > 0) {
            storage_unpin_chunk(old_hash);
            fault_inject_point("before_release_chunk");
            if (strcmp(old_hash, new_hash) != 0) {
                storage_release_chunk(old_hash);
            }
            fault_inject_point("after_release_chunk");
        }

        bytes_written += write_len;
    }

    if (offset + size > node->size) {
        node->size = offset + size;
    }
    node->mtime = time(NULL);

    // Update baseline entropy if not quarantined
    if (!node->is_quarantined) {
        double curr_ent = entropy_calculate((const unsigned char *)buf, size);
        if (node->baseline_entropy == 0.0) {
            node->baseline_entropy = curr_ent;
        } else {
            // Exponential moving average: 80% previous, 20% new
            node->baseline_entropy = (0.80 * node->baseline_entropy) + (0.20 * curr_ent);
        }
    }

    inode_save();
    return (int)bytes_written;
}

int inode_read(VaultInode *node, char *buf, size_t size, off_t offset) {
    if (!node || S_ISDIR(node->mode)) return -EISDIR;
    if (offset >= (off_t)node->size) return 0;

    size_t available = node->size - offset;
    size_t to_read = (size < available) ? size : available;
    size_t bytes_read = 0;

    while (bytes_read < to_read) {
        off_t current_pos = offset + bytes_read;
        size_t chunk_idx = current_pos / VAULTFS_BLOCK_SIZE;
        size_t chunk_offset = current_pos % VAULTFS_BLOCK_SIZE;
        size_t chunk_remain = VAULTFS_BLOCK_SIZE - chunk_offset;
        size_t copy_len = to_read - bytes_read;
        if (copy_len > chunk_remain) copy_len = chunk_remain;

        if (chunk_idx >= node->chunk_count) break;

        unsigned char chunk_buf[VAULTFS_BLOCK_SIZE];
        size_t chunk_len = 0;
        int res = storage_read_chunk(node->chunk_hashes[chunk_idx], chunk_buf, &chunk_len);
        if (res != 0) return res;

        if (chunk_offset < chunk_len) {
            size_t avail_in_chunk = chunk_len - chunk_offset;
            if (copy_len > avail_in_chunk) copy_len = avail_in_chunk;
            memcpy(buf + bytes_read, chunk_buf + chunk_offset, copy_len);
        } else {
            memset(buf + bytes_read, 0, copy_len);
        }

        bytes_read += copy_len;
    }

    node->atime = time(NULL);
    return (int)bytes_read;
}

int inode_truncate(VaultInode *node, off_t new_size) {
    if (!node || S_ISDIR(node->mode)) return -EISDIR;

    // RansomShield Protection against O_TRUNC encryption wipes:
    // If a file with content is being truncated to 0, preserve existing chunks into ghost quarantine tomb
    if (new_size == 0 && node->chunk_count > 0 && !node->is_quarantined) {
        node->ghost_size = node->size;
        node->ghost_chunk_count = node->chunk_count;
        for (uint32_t c = 0; c < node->chunk_count; c++) {
            strcpy(node->ghost_chunk_hashes[c], node->chunk_hashes[c]);
            storage_retain_chunk(node->ghost_chunk_hashes[c]);
        }
    }

    size_t new_chunk_count = (new_size + VAULTFS_BLOCK_SIZE - 1) / VAULTFS_BLOCK_SIZE;

    if (new_chunk_count < node->chunk_count) {
        uint64_t txid = wal_begin_tx();

        // Step 1: Pin and log all chunks about to be truncated
        for (size_t i = new_chunk_count; i < node->chunk_count; i++) {
            wal_log_pre_truncate(txid, node->ino, (uint32_t)i, node->chunk_hashes[i], node->size, new_size);
        }

        fault_inject_point("during_truncate");

        // Step 2: Clear chunk hashes and release blocks
        for (size_t i = new_chunk_count; i < node->chunk_count; i++) {
            char old_h[VAULTFS_HASH_HEX_LEN + 1];
            strcpy(old_h, node->chunk_hashes[i]);
            node->chunk_hashes[i][0] = '\0';
            storage_unpin_chunk(old_h);
            storage_release_chunk(old_h);
        }
        node->chunk_count = (uint32_t)new_chunk_count;

        wal_commit_tx(txid);
    }

    node->size = (uint64_t)new_size;
    node->mtime = time(NULL);
    inode_save();
    return 0;
}

int inode_unlink(const char *path) {
    VaultInode *node = inode_lookup(path);
    if (!node) return -ENOENT;
    if (S_ISDIR(node->mode)) return -EISDIR;

    for (uint32_t i = 0; i < node->chunk_count; i++) {
        storage_release_chunk(node->chunk_hashes[i]);
    }

    // Release any ghost chunks if file was quarantined
    if (node->is_quarantined) {
        for (uint32_t i = 0; i < node->ghost_chunk_count; i++) {
            storage_release_chunk(node->ghost_chunk_hashes[i]);
        }
    }

    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        if (g_vaultfs.inodes[i].ino == node->ino) {
            g_vaultfs.inodes[i] = g_vaultfs.inodes[g_vaultfs.inode_count - 1];
            g_vaultfs.inode_count--;
            break;
        }
    }

    inode_save();
    return 0;
}

int inode_rmdir(const char *path) {
    VaultInode *node = inode_lookup(path);
    if (!node) return -ENOENT;
    if (!S_ISDIR(node->mode)) return -ENOTDIR;
    if (node->ino == 1) return -EBUSY;

    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        if (g_vaultfs.inodes[i].parent_ino == node->ino) {
            return -ENOTEMPTY;
        }
    }

    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        if (g_vaultfs.inodes[i].ino == node->ino) {
            g_vaultfs.inodes[i] = g_vaultfs.inodes[g_vaultfs.inode_count - 1];
            g_vaultfs.inode_count--;
            break;
        }
    }

    inode_save();
    return 0;
}

int inode_heal_quarantine(void) {
    int healed_count = 0;

    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        VaultInode *node = &g_vaultfs.inodes[i];
        if (node->is_quarantined && node->ghost_chunk_count > 0) {
            // 1. Release corrupted/encrypted blocks written by ransomware
            for (uint32_t c = 0; c < node->chunk_count; c++) {
                storage_release_chunk(node->chunk_hashes[c]);
            }

            // 2. Restore original ghost blocks
            node->chunk_count = node->ghost_chunk_count;
            node->size = node->ghost_size;
            for (uint32_t c = 0; c < node->ghost_chunk_count; c++) {
                strcpy(node->chunk_hashes[c], node->ghost_chunk_hashes[c]);
            }

            // 3. Clear quarantine flags
            node->is_quarantined = false;
            node->ghost_chunk_count = 0;
            node->ghost_size = 0;
            node->mtime = time(NULL);
            healed_count++;
        }
    }

    if (healed_count > 0) {
        g_vaultfs.files_quarantined = 0;
        inode_save();
        storage_save_catalog();
    }
    return healed_count;
}

void inode_save(void) {
    char path[VAULTFS_MAX_PATH * 2];
    char tmp_path[VAULTFS_MAX_PATH * 2];
    snprintf(path, sizeof(path), "%s/metadata/inodes.dat", g_vaultfs.backing_dir);
    snprintf(tmp_path, sizeof(tmp_path), "%s/metadata/inodes.dat.tmp", g_vaultfs.backing_dir);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;

    ssize_t w1 = write(fd, &g_vaultfs.inode_count, sizeof(uint32_t));
    ssize_t w2 = write(fd, &g_vaultfs.next_ino, sizeof(uint64_t));
    ssize_t w3 = write(fd, &g_vaultfs.ransomware_attacks_detected, sizeof(uint32_t));
    ssize_t w4 = write(fd, &g_vaultfs.files_quarantined, sizeof(uint32_t));
    ssize_t w5 = write(fd, g_vaultfs.inodes, sizeof(VaultInode) * g_vaultfs.inode_count);
    (void)w1; (void)w2; (void)w3; (void)w4; (void)w5;

    fdatasync(fd);
    close(fd);
    rename(tmp_path, path);
}

void inode_load(void) {
    char path[VAULTFS_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/metadata/inodes.dat", g_vaultfs.backing_dir);

    FILE *f = fopen(path, "rb");
    if (!f) return;

    if (fread(&g_vaultfs.inode_count, sizeof(uint32_t), 1, f) == 1 &&
        fread(&g_vaultfs.next_ino, sizeof(uint64_t), 1, f) == 1) {
        if (g_vaultfs.inode_count > VAULTFS_MAX_INODES) {
            g_vaultfs.inode_count = VAULTFS_MAX_INODES;
        }
        // Read RansomShield counters if present
        if (fread(&g_vaultfs.ransomware_attacks_detected, sizeof(uint32_t), 1, f) != 1 ||
            fread(&g_vaultfs.files_quarantined, sizeof(uint32_t), 1, f) != 1) {
            g_vaultfs.ransomware_attacks_detected = 0;
            g_vaultfs.files_quarantined = 0;
        }
        size_t read_items = fread(g_vaultfs.inodes, sizeof(VaultInode), g_vaultfs.inode_count, f);
        (void)read_items;
    }
    fclose(f);
}
