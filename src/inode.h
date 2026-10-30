#ifndef VAULTFS_INODE_H
#define VAULTFS_INODE_H

#include "vaultfs.h"

int         inode_init(void);
VaultInode *inode_lookup(const char *path);
VaultInode *inode_get_by_id(uint64_t ino);
int         inode_create(const char *path, mode_t mode, VaultInode **out_node);
int         inode_unlink(const char *path, pid_t pid, pid_t tree_root);
int         inode_rmdir(const char *path);
int         inode_write(VaultInode *node, const char *buf, size_t size, off_t offset, pid_t pid, pid_t tree_root);
int         inode_read(VaultInode *node, char *buf, size_t size, off_t offset);
int         inode_truncate(VaultInode *node, off_t new_size, pid_t pid, pid_t tree_root);
int         inode_rename(const char *oldpath, const char *newpath, pid_t pid, pid_t tree_root);
int         inode_heal_quarantine(void);
int         inode_heal_tree(pid_t tree_root);
void        inode_save(void);
void        inode_load(void);

#endif // VAULTFS_INODE_H
