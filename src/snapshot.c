#include "snapshot.h"
#include "inode.h"
#include "storage.h"

int snapshot_init(void) {
    g_vaultfs.snapshot_count = 0;

    char snap_dir[VAULTFS_MAX_PATH + 64];
    snprintf(snap_dir, sizeof(snap_dir), "%s/snapshots", g_vaultfs.backing_dir);

    DIR *d = opendir(snap_dir);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        char *dot = strrchr(ent->d_name, '.');
        if (dot && strcmp(dot, ".snap") == 0) {
            char name[VAULTFS_MAX_NAME];
            size_t name_len = dot - ent->d_name;
            if (name_len >= sizeof(name)) name_len = sizeof(name) - 1;
            strncpy(name, ent->d_name, name_len);
            name[name_len] = '\0';

            char snap_path[VAULTFS_MAX_PATH * 2];
            snprintf(snap_path, sizeof(snap_path), "%s/%s", snap_dir, ent->d_name);

            FILE *f = fopen(snap_path, "rb");
            if (f) {
                if (g_vaultfs.snapshot_count < VAULTFS_MAX_SNAPSHOTS) {
                    VaultSnapshot *s = &g_vaultfs.snapshots[g_vaultfs.snapshot_count];
                    strcpy(s->name, name);
                    if (fread(&s->created_at, sizeof(time_t), 1, f) == 1 &&
                        fread(&s->inode_count, sizeof(uint32_t), 1, f) == 1) {
                        s->inodes = calloc(s->inode_count, sizeof(VaultInode));
                        if (s->inodes) {
                            size_t read_items = fread(s->inodes, sizeof(VaultInode), s->inode_count, f);
                            (void)read_items;
                            g_vaultfs.snapshot_count++;
                        }
                    }
                }
                fclose(f);
            }
        }
    }
    closedir(d);
    return 0;
}

int snapshot_create(const char *name) {
    if (!name || strlen(name) == 0) return -EINVAL;

    // Check for duplicate snapshot name
    for (uint32_t i = 0; i < g_vaultfs.snapshot_count; i++) {
        if (strcmp(g_vaultfs.snapshots[i].name, name) == 0) {
            return -EEXIST;
        }
    }

    if (g_vaultfs.snapshot_count >= VAULTFS_MAX_SNAPSHOTS) {
        return -ENOSPC;
    }

    VaultSnapshot *snap = &g_vaultfs.snapshots[g_vaultfs.snapshot_count];
    strncpy(snap->name, name, sizeof(snap->name) - 1);
    snap->created_at = time(NULL);
    snap->inode_count = g_vaultfs.inode_count;
    snap->inodes = calloc(snap->inode_count, sizeof(VaultInode));
    if (!snap->inodes) return -ENOMEM;

    // Deep-copy active inode table
    memcpy(snap->inodes, g_vaultfs.inodes, sizeof(VaultInode) * snap->inode_count);

    // Increment refcount of all referenced chunks so they cannot be deleted
    for (uint32_t i = 0; i < snap->inode_count; i++) {
        for (uint32_t c = 0; c < snap->inodes[i].chunk_count; c++) {
            storage_retain_chunk(snap->inodes[i].chunk_hashes[c]);
        }
    }

    // Persist snapshot to disk
    char snap_path[VAULTFS_MAX_PATH * 2];
    snprintf(snap_path, sizeof(snap_path), "%s/snapshots/%s.snap", g_vaultfs.backing_dir, name);

    FILE *f = fopen(snap_path, "wb");
    if (!f) {
        free(snap->inodes);
        return -EIO;
    }

    fwrite(&snap->created_at, sizeof(time_t), 1, f);
    fwrite(&snap->inode_count, sizeof(uint32_t), 1, f);
    fwrite(snap->inodes, sizeof(VaultInode), snap->inode_count, f);
    fclose(f);

    g_vaultfs.snapshot_count++;
    return 0;
}

int snapshot_restore(const char *name) {
    int idx = -1;
    for (uint32_t i = 0; i < g_vaultfs.snapshot_count; i++) {
        if (strcmp(g_vaultfs.snapshots[i].name, name) == 0) {
            idx = (int)i;
            break;
        }
    }
    if (idx < 0) return -ENOENT;

    VaultSnapshot *snap = &g_vaultfs.snapshots[idx];

    // 1. Release all chunks in active filesystem
    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        for (uint32_t c = 0; c < g_vaultfs.inodes[i].chunk_count; c++) {
            storage_release_chunk(g_vaultfs.inodes[i].chunk_hashes[c]);
        }
    }

    // 2. Replace active inode table with snapshot's inode table
    g_vaultfs.inode_count = snap->inode_count;
    memcpy(g_vaultfs.inodes, snap->inodes, sizeof(VaultInode) * snap->inode_count);

    // 3. Retain chunks for the newly restored active filesystem
    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        for (uint32_t c = 0; c < g_vaultfs.inodes[i].chunk_count; c++) {
            storage_retain_chunk(g_vaultfs.inodes[i].chunk_hashes[c]);
        }
    }

    inode_save();
    return 0;
}

int snapshot_delete(const char *name) {
    int idx = -1;
    for (uint32_t i = 0; i < g_vaultfs.snapshot_count; i++) {
        if (strcmp(g_vaultfs.snapshots[i].name, name) == 0) {
            idx = (int)i;
            break;
        }
    }
    if (idx < 0) return -ENOENT;

    VaultSnapshot *snap = &g_vaultfs.snapshots[idx];

    // Release chunk references held by the snapshot
    for (uint32_t i = 0; i < snap->inode_count; i++) {
        for (uint32_t c = 0; c < snap->inodes[i].chunk_count; c++) {
            storage_release_chunk(snap->inodes[i].chunk_hashes[c]);
        }
    }

    free(snap->inodes);

    // Delete snapshot file from disk
    char snap_path[VAULTFS_MAX_PATH * 2];
    snprintf(snap_path, sizeof(snap_path), "%s/snapshots/%s.snap", g_vaultfs.backing_dir, name);
    unlink(snap_path);

    // Shift array
    for (uint32_t i = idx; i < g_vaultfs.snapshot_count - 1; i++) {
        g_vaultfs.snapshots[i] = g_vaultfs.snapshots[i + 1];
    }
    g_vaultfs.snapshot_count--;

    return 0;
}

void snapshot_list_print(void) {
    printf("+-------------------------------------------------------------------------+\n");
    printf("| Active Snapshots (Point-in-Time Historical Trees)                      |\n");
    printf("+----------------------+---------------------+-------------+--------------+\n");
    printf("| Snapshot Name        | Created At          | Inode Count | Total Size   |\n");
    printf("+----------------------+---------------------+-------------+--------------+\n");

    for (uint32_t i = 0; i < g_vaultfs.snapshot_count; i++) {
        VaultSnapshot *s = &g_vaultfs.snapshots[i];
        char time_str[32];
        struct tm *tm_info = localtime(&s->created_at);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        uint64_t total_size = 0;
        for (uint32_t j = 0; j < s->inode_count; j++) {
            total_size += s->inodes[j].size;
        }

        printf("| %-20s | %-19s | %-11u | %-12lu |\n",
               s->name, time_str, s->inode_count, total_size);
    }
    printf("+----------------------+---------------------+-------------+--------------+\n");
}
