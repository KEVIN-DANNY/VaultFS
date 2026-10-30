#ifndef VAULTFS_PROC_TREE_H
#define VAULTFS_PROC_TREE_H

#include "vaultfs.h"

/**
 * Initialize process tree resolver and LRU cache.
 */
void  proc_tree_init(void);

/**
 * Resolve a process PID to its highest user ancestor (process-tree root)
 * by walking the ppid chain in /proc/<pid>/stat.
 * Uses a short TTL cache to avoid frequent /proc disk reads.
 * Gracefully handles short-lived processes that have exited.
 */
pid_t proc_tree_get_root(pid_t pid);

/**
 * Invalidate process tree cache.
 */
void  proc_tree_clear_cache(void);

#endif // VAULTFS_PROC_TREE_H
