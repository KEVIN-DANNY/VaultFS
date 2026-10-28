#ifndef VAULTFS_SNAPSHOT_H
#define VAULTFS_SNAPSHOT_H

#include "vaultfs.h"

int  snapshot_init(void);
int  snapshot_create(const char *name);
int  snapshot_restore(const char *name);
int  snapshot_delete(const char *name);
void snapshot_list_print(void);

#endif // VAULTFS_SNAPSHOT_H
