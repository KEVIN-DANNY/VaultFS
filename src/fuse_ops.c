#include "fuse_ops.h"
#include "inode.h"
#include "snapshot.h"
#include "storage.h"
#include "proc_tree.h"
#include "write_log.h"

static int vaultfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    memset(stbuf, 0, sizeof(struct stat));

    // Handle magic virtual .snapshots directory
    if (strcmp(path, "/.snapshots") == 0) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        stbuf->st_size = 4096;
        stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
        return 0;
    }

    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *node = inode_lookup(path);
    if (!node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }

    stbuf->st_ino = node->ino;
    stbuf->st_mode = node->mode;
    stbuf->st_nlink = S_ISDIR(node->mode) ? 2 : 1;
    stbuf->st_uid = node->uid;
    stbuf->st_gid = node->gid;
    stbuf->st_size = node->size;
    stbuf->st_atime = node->atime;
    stbuf->st_mtime = node->mtime;
    stbuf->st_ctime = node->ctime;
    stbuf->st_blksize = VAULTFS_BLOCK_SIZE;
    stbuf->st_blocks = (node->size + 511) / 512;

    pthread_mutex_unlock(&g_vaultfs.lock);
    return 0;
}

static int vaultfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                           off_t offset, struct fuse_file_info *fi,
                           enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;

    // Standard directory entries
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    // If reading root, add virtual .snapshots entry
    if (strcmp(path, "/") == 0) {
        filler(buf, ".snapshots", NULL, 0, 0);
    }

    // Virtual .snapshots directory
    if (strcmp(path, "/.snapshots") == 0) {
        pthread_mutex_lock(&g_vaultfs.lock);
        for (uint32_t i = 0; i < g_vaultfs.snapshot_count; i++) {
            filler(buf, g_vaultfs.snapshots[i].name, NULL, 0, 0);
        }
        pthread_mutex_unlock(&g_vaultfs.lock);
        return 0;
    }

    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *dir_node = inode_lookup(path);
    if (!dir_node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }

    if (!S_ISDIR(dir_node->mode)) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOTDIR;
    }

    for (uint32_t i = 0; i < g_vaultfs.inode_count; i++) {
        VaultInode *child = &g_vaultfs.inodes[i];
        if (child->parent_ino == dir_node->ino && child->ino != dir_node->ino) {
            struct stat st;
            memset(&st, 0, sizeof(st));
            st.st_ino = child->ino;
            st.st_mode = child->mode;
            filler(buf, child->name, &st, 0, 0);
        }
    }

    pthread_mutex_unlock(&g_vaultfs.lock);
    return 0;
}

static int vaultfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)fi;
    pthread_mutex_lock(&g_vaultfs.lock);
    int res = inode_create(path, S_IFREG | mode, NULL);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_open(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *node = inode_lookup(path);
    if (!node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }
    if (S_ISDIR(node->mode)) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -EISDIR;
    }
    pthread_mutex_unlock(&g_vaultfs.lock);
    return 0;
}

static int vaultfs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi) {
    (void)fi;
    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *node = inode_lookup(path);
    if (!node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }
    int res = inode_read(node, buf, size, offset);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_write(const char *path, const char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
    (void)fi;
    struct fuse_context *ctx = fuse_get_context();
    pid_t pid = ctx ? ctx->pid : getpid();
    pid_t tree_root = proc_tree_get_root(pid);

    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *node = inode_lookup(path);
    if (!node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }
    int res = inode_write(node, buf, size, offset, pid, tree_root);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi;
    struct fuse_context *ctx = fuse_get_context();
    pid_t pid = ctx ? ctx->pid : getpid();
    pid_t tree_root = proc_tree_get_root(pid);

    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *node = inode_lookup(path);
    if (!node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }
    int res = inode_truncate(node, size, pid, tree_root);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_unlink(const char *path) {
    struct fuse_context *ctx = fuse_get_context();
    pid_t pid = ctx ? ctx->pid : getpid();
    pid_t tree_root = proc_tree_get_root(pid);

    pthread_mutex_lock(&g_vaultfs.lock);
    int res = inode_unlink(path, pid, tree_root);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_rename(const char *oldpath, const char *newpath, unsigned int flags) {
    (void)flags;
    struct fuse_context *ctx = fuse_get_context();
    pid_t pid = ctx ? ctx->pid : getpid();
    pid_t tree_root = proc_tree_get_root(pid);

    pthread_mutex_lock(&g_vaultfs.lock);
    int res = inode_rename(oldpath, newpath, pid, tree_root);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_mkdir(const char *path, mode_t mode) {
    pthread_mutex_lock(&g_vaultfs.lock);
    int res = inode_create(path, S_IFDIR | mode, NULL);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_rmdir(const char *path) {
    pthread_mutex_lock(&g_vaultfs.lock);
    int res = inode_rmdir(path);
    pthread_mutex_unlock(&g_vaultfs.lock);
    return res;
}

static int vaultfs_statfs(const char *path, struct statvfs *stbuf) {
    (void)path;
    memset(stbuf, 0, sizeof(struct statvfs));

    VaultFSStats stats;
    storage_get_stats(&stats);

    stbuf->f_bsize = VAULTFS_BLOCK_SIZE;
    stbuf->f_frsize = VAULTFS_BLOCK_SIZE;
    stbuf->f_blocks = 10000000;              // Simulated 40 GB capacity
    stbuf->f_bfree = 10000000 - stats.unique_blocks;
    stbuf->f_bavail = stbuf->f_bfree;
    stbuf->f_files = VAULTFS_MAX_INODES;
    stbuf->f_ffree = VAULTFS_MAX_INODES - g_vaultfs.inode_count;
    stbuf->f_namemax = VAULTFS_MAX_NAME;

    return 0;
}

static int vaultfs_utimens(const char *path, const struct timespec tv[2],
                           struct fuse_file_info *fi) {
    (void)fi;
    pthread_mutex_lock(&g_vaultfs.lock);
    VaultInode *node = inode_lookup(path);
    if (!node) {
        pthread_mutex_unlock(&g_vaultfs.lock);
        return -ENOENT;
    }
    node->atime = tv[0].tv_sec;
    node->mtime = tv[1].tv_sec;
    inode_save();
    pthread_mutex_unlock(&g_vaultfs.lock);
    return 0;
}

static struct fuse_operations s_vaultfs_ops = {
    .getattr  = vaultfs_getattr,
    .readdir  = vaultfs_readdir,
    .create   = vaultfs_create,
    .open     = vaultfs_open,
    .read     = vaultfs_read,
    .write    = vaultfs_write,
    .truncate = vaultfs_truncate,
    .unlink   = vaultfs_unlink,
    .rename   = vaultfs_rename,
    .mkdir    = vaultfs_mkdir,
    .rmdir    = vaultfs_rmdir,
    .statfs   = vaultfs_statfs,
    .utimens  = vaultfs_utimens,
};

struct fuse_operations *vaultfs_get_operations(void) {
    return &s_vaultfs_ops;
}
