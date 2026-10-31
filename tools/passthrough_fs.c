#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <stdlib.h>
#include <stdbool.h>

static char s_source_dir[1024];

static void get_full_path(char *fpath, const char *path) {
    snprintf(fpath, 1024, "%s%s", s_source_dir, path);
}

static int pt_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char fpath[1024];
    get_full_path(fpath, path);
    int res = lstat(fpath, stbuf);
    if (res == -1) return -errno;
    return 0;
}

static int pt_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    char fpath[1024];
    get_full_path(fpath, path);
    DIR *dp = opendir(fpath);
    if (!dp) return -errno;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp);
    return 0;
}

static int pt_open(const char *path, struct fuse_file_info *fi) {
    char fpath[1024];
    get_full_path(fpath, path);
    int fd = open(fpath, fi->flags);
    if (fd == -1) return -errno;
    fi->fh = fd;
    return 0;
}

static int pt_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char fpath[1024];
    get_full_path(fpath, path);
    int fd = open(fpath, fi->flags, mode);
    if (fd == -1) return -errno;
    fi->fh = fd;
    return 0;
}

static int pt_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    (void)path;
    int fd = (fi && fi->fh > 0) ? (int)fi->fh : -1;
    bool opened_here = false;
    if (fd == -1) {
        char fpath[1024];
        get_full_path(fpath, path);
        fd = open(fpath, O_RDONLY);
        if (fd == -1) return -errno;
        opened_here = true;
    }
    ssize_t res = pread(fd, buf, size, offset);
    if (opened_here) close(fd);
    if (res == -1) return -errno;
    return (int)res;
}

static int pt_write(const char *path, const char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    (void)path;
    int fd = (fi && fi->fh > 0) ? (int)fi->fh : -1;
    bool opened_here = false;
    if (fd == -1) {
        char fpath[1024];
        get_full_path(fpath, path);
        fd = open(fpath, O_WRONLY);
        if (fd == -1) return -errno;
        opened_here = true;
    }
    ssize_t res = pwrite(fd, buf, size, offset);
    if (opened_here) close(fd);
    if (res == -1) return -errno;
    return (int)res;
}

static int pt_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi;
    char fpath[1024];
    get_full_path(fpath, path);
    int res = truncate(fpath, size);
    if (res == -1) return -errno;
    return 0;
}

static int pt_unlink(const char *path) {
    char fpath[1024];
    get_full_path(fpath, path);
    int res = unlink(fpath);
    if (res == -1) return -errno;
    return 0;
}

static int pt_mkdir(const char *path, mode_t mode) {
    char fpath[1024];
    get_full_path(fpath, path);
    int res = mkdir(fpath, mode);
    if (res == -1) return -errno;
    return 0;
}

static int pt_rmdir(const char *path) {
    char fpath[1024];
    get_full_path(fpath, path);
    int res = rmdir(fpath);
    if (res == -1) return -errno;
    return 0;
}

static int pt_statfs(const char *path, struct statvfs *stbuf) {
    char fpath[1024];
    get_full_path(fpath, path);
    int res = statvfs(fpath, stbuf);
    if (res == -1) return -errno;
    return 0;
}

static int pt_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    if (fi && fi->fh > 0) {
        close((int)fi->fh);
    }
    return 0;
}

static struct fuse_operations s_pt_ops = {
    .getattr  = pt_getattr,
    .readdir  = pt_readdir,
    .open     = pt_open,
    .create   = pt_create,
    .read     = pt_read,
    .write    = pt_write,
    .truncate = pt_truncate,
    .unlink   = pt_unlink,
    .mkdir    = pt_mkdir,
    .rmdir    = pt_rmdir,
    .statfs   = pt_statfs,
    .release  = pt_release,
};

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <source_dir> <mount_dir> [FUSE options]\n", argv[0]);
        return 1;
    }
    strncpy(s_source_dir, argv[1], sizeof(s_source_dir) - 1);

    char *fuse_argv[32];
    int fuse_argc = 0;
    fuse_argv[fuse_argc++] = argv[0];
    fuse_argv[fuse_argc++] = argv[2]; // Mountpoint
    for (int i = 3; i < argc; i++) {
        if (fuse_argc < 30) {
            fuse_argv[fuse_argc++] = argv[i];
        }
    }
    return fuse_main(fuse_argc, fuse_argv, &s_pt_ops, NULL);
}
