#ifndef VAULTFS_STORAGE_H
#define VAULTFS_STORAGE_H

#include "vaultfs.h"

int  storage_init(const char *backing_dir);
int  storage_write_chunk(const unsigned char *data, size_t len, char *hash_out);
int  storage_read_chunk(const char *hash, unsigned char *data_out, size_t *len_out);
int  storage_retain_chunk(const char *hash);
int  storage_release_chunk(const char *hash);
void storage_get_stats(VaultFSStats *stats);
void storage_save_catalog(void);
void storage_load_catalog(void);

#endif // VAULTFS_STORAGE_H
