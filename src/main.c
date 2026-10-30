#include "vaultfs.h"
#include "crypto.h"
#include "storage.h"
#include "inode.h"
#include "snapshot.h"
#include "fuse_ops.h"
#include "wal.h"

VaultFSContext g_vaultfs;

static void print_usage(const char *prog) {
    fprintf(stderr, "VaultFS: Snapshotting, Encrypted & Deduplicated File System\n\n");
    fprintf(stderr, "Usage: %s <storage_dir> <mount_point> [OPTIONS] [FUSE_OPTIONS]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --password <secret>   Master password for AES-256 encryption\n");
    fprintf(stderr, "  -d, --debug               Run FUSE in foreground with debug logs\n");
    fprintf(stderr, "  -h, --help                Show this help message\n\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s /var/vaultfs_data /mnt/secure -p MySecretKey\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    memset(&g_vaultfs, 0, sizeof(VaultFSContext));
    pthread_mutex_init(&g_vaultfs.lock, NULL);

    // Extract storage_dir and mount_point
    strncpy(g_vaultfs.backing_dir, argv[1], sizeof(g_vaultfs.backing_dir) - 1);
    strncpy(g_vaultfs.mount_point, argv[2], sizeof(g_vaultfs.mount_point) - 1);

    // Filter arguments for FUSE and VaultFS custom flags
    char *fuse_argv[64];
    int fuse_argc = 0;
    fuse_argv[fuse_argc++] = argv[0];
    fuse_argv[fuse_argc++] = argv[2]; // Mountpoint is first positional arg for FUSE

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) {
            if (i + 1 < argc) {
                strncpy(g_vaultfs.password, argv[++i], sizeof(g_vaultfs.password) - 1);
            }
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            g_vaultfs.debug = true;
            fuse_argv[fuse_argc++] = "-d";
        } else if (strcmp(argv[i], "-f") == 0) {
            fuse_argv[fuse_argc++] = "-f"; // Foreground mode
        } else if (strcmp(argv[i], "-s") == 0) {
            fuse_argv[fuse_argc++] = "-s"; // Single-threaded mode
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            // Forward other options to FUSE (e.g. -o allow_other)
            if (fuse_argc < 60) {
                fuse_argv[fuse_argc++] = argv[i];
            }
        }
    }

    printf("===================================================================\n");
    printf("   VaultFS: Encrypted, Content-Deduplicated & Snapshotting FS     \n");
    printf("===================================================================\n");
    printf("[*] Backing Storage Directory : %s\n", g_vaultfs.backing_dir);
    printf("[*] Virtual FUSE Mountpoint   : %s\n", g_vaultfs.mount_point);
    printf("[*] AES-256 Encryption Mode   : Convergent AES-256-CBC Enabled\n");
    printf("[*] Content Deduplication     : SHA-256 Block-Level Hash Engine\n");
    printf("[*] Time-Travel Snapshots     : Copy-On-Write (Zero-Copy) Engine\n");
    printf("[*] RansomShield Active Guard : Real-Time Entropy Interception Enabled\n");
    printf("===================================================================\n");

    // Initialize subsystems
    crypto_init(g_vaultfs.password);
    if (storage_init(g_vaultfs.backing_dir) != 0) {
        fprintf(stderr, "Error: Failed to initialize storage engine at %s\n", g_vaultfs.backing_dir);
        return 1;
    }

    if (inode_init() != 0) {
        fprintf(stderr, "Error: Failed to initialize inode manager\n");
        return 1;
    }

    if (snapshot_init() != 0) {
        fprintf(stderr, "Warning: Failed to load snapshots\n");
    }

    // Initialize Write-Ahead Intent Logging & Crash Consistency Engine
    if (wal_init(g_vaultfs.backing_dir) != 0) {
        fprintf(stderr, "Warning: Failed to initialize WAL subsystem\n");
    } else {
        printf("[*] Write-Ahead Intent Log    : Durability & Pre-Image Pinning ACTIVE\n");
        int recovered = wal_recover_and_replay();
        if (recovered > 0) {
            printf("[+] Replayed and recovered %d uncommitted transaction(s) after crash.\n", recovered);
        }
    }

    printf("[+] Subsystems initialized successfully. Starting FUSE loop...\n\n");

    // Run FUSE main event loop
    int ret = fuse_main(fuse_argc, fuse_argv, vaultfs_get_operations(), NULL);

    // Clean exit: flush metadata and close WAL
    wal_close();
    storage_save_catalog();
    inode_save();

    return ret;
}
