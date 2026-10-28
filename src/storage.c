#include "storage.h"
#include "crypto.h"

#define MAX_CATALOG_ENTRIES 65536

typedef struct {
    char     hash[VAULTFS_HASH_HEX_LEN + 1];
    uint32_t ref_count;
    uint32_t disk_size;
    uint32_t original_size;
} CatalogEntry;

static CatalogEntry s_catalog[MAX_CATALOG_ENTRIES];
static uint32_t     s_catalog_count = 0;
static pthread_mutex_t s_storage_lock = PTHREAD_MUTEX_INITIALIZER;

static int find_catalog_entry(const char *hash) {
    for (uint32_t i = 0; i < s_catalog_count; i++) {
        if (strcmp(s_catalog[i].hash, hash) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void get_block_path(const char *hash, char *path_out, size_t max_len) {
    snprintf(path_out, max_len, "%s/blocks/%s", g_vaultfs.backing_dir, hash);
}

int storage_init(const char *backing_dir) {
    char path[VAULTFS_MAX_PATH + 64];

    // Create backing directories
    snprintf(path, sizeof(path), "%s", backing_dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/blocks", backing_dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/metadata", backing_dir);
    mkdir(path, 0755);

    snprintf(path, sizeof(path), "%s/snapshots", backing_dir);
    mkdir(path, 0755);

    storage_load_catalog();
    return 0;
}

int storage_write_chunk(const unsigned char *data, size_t len, char *hash_out) {
    pthread_mutex_lock(&s_storage_lock);

    // 1. Calculate Content Hash (SHA-256)
    crypto_sha256(data, len, hash_out);

    // 2. Check if chunk already exists (DEDUPLICATION)
    int idx = find_catalog_entry(hash_out);
    if (idx >= 0) {
        // Chunk exists: increment reference count without writing new disk block!
        s_catalog[idx].ref_count++;
        storage_save_catalog();
        pthread_mutex_unlock(&s_storage_lock);
        return 0;
    }

    // 3. Encrypt chunk via Convergent AES-256
    unsigned char *ciphertext = NULL;
    size_t ct_len = 0;
    if (crypto_encrypt(data, len, hash_out, &ciphertext, &ct_len) != 0) {
        pthread_mutex_unlock(&s_storage_lock);
        return -1;
    }

    // 4. Write encrypted block to disk
    char block_path[VAULTFS_MAX_PATH + 128];
    get_block_path(hash_out, block_path, sizeof(block_path));

    int fd = open(block_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(ciphertext);
        pthread_mutex_unlock(&s_storage_lock);
        return -1;
    }

    ssize_t written = write(fd, ciphertext, ct_len);
    close(fd);
    free(ciphertext);

    if (written < 0 || (size_t)written != ct_len) {
        unlink(block_path);
        pthread_mutex_unlock(&s_storage_lock);
        return -1;
    }

    // 5. Add to catalog
    if (s_catalog_count < MAX_CATALOG_ENTRIES) {
        strncpy(s_catalog[s_catalog_count].hash, hash_out, VAULTFS_HASH_HEX_LEN);
        s_catalog[s_catalog_count].hash[VAULTFS_HASH_HEX_LEN] = '\0';
        s_catalog[s_catalog_count].ref_count = 1;
        s_catalog[s_catalog_count].disk_size = (uint32_t)ct_len;
        s_catalog[s_catalog_count].original_size = (uint32_t)len;
        s_catalog_count++;
    }

    storage_save_catalog();
    pthread_mutex_unlock(&s_storage_lock);
    return 0;
}

int storage_read_chunk(const char *hash, unsigned char *data_out, size_t *len_out) {
    pthread_mutex_lock(&s_storage_lock);

    char block_path[VAULTFS_MAX_PATH + 128];
    get_block_path(hash, block_path, sizeof(block_path));

    int fd = open(block_path, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&s_storage_lock);
        return -ENOENT;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        pthread_mutex_unlock(&s_storage_lock);
        return -EIO;
    }

    unsigned char *ct = malloc(st.st_size);
    if (!ct) {
        close(fd);
        pthread_mutex_unlock(&s_storage_lock);
        return -ENOMEM;
    }

    ssize_t rd = read(fd, ct, st.st_size);
    close(fd);

    if (rd != st.st_size) {
        free(ct);
        pthread_mutex_unlock(&s_storage_lock);
        return -EIO;
    }

    // Decrypt chunk
    size_t pt_len = 0;
    if (crypto_decrypt(ct, st.st_size, hash, data_out, &pt_len) != 0) {
        free(ct);
        pthread_mutex_unlock(&s_storage_lock);
        return -EIO;
    }
    free(ct);

    *len_out = pt_len;
    pthread_mutex_unlock(&s_storage_lock);
    return 0;
}

int storage_retain_chunk(const char *hash) {
    pthread_mutex_lock(&s_storage_lock);
    int idx = find_catalog_entry(hash);
    if (idx >= 0) {
        s_catalog[idx].ref_count++;
        storage_save_catalog();
        pthread_mutex_unlock(&s_storage_lock);
        return 0;
    }
    pthread_mutex_unlock(&s_storage_lock);
    return -1;
}

int storage_release_chunk(const char *hash) {
    pthread_mutex_lock(&s_storage_lock);
    int idx = find_catalog_entry(hash);
    if (idx < 0) {
        pthread_mutex_unlock(&s_storage_lock);
        return -ENOENT;
    }

    if (s_catalog[idx].ref_count > 1) {
        s_catalog[idx].ref_count--;
    } else {
        // Last reference: delete physical block file
        char block_path[VAULTFS_MAX_PATH + 128];
        get_block_path(hash, block_path, sizeof(block_path));
        unlink(block_path);

        // Remove from catalog
        s_catalog[idx] = s_catalog[s_catalog_count - 1];
        s_catalog_count--;
    }

    storage_save_catalog();
    pthread_mutex_unlock(&s_storage_lock);
    return 0;
}

void storage_get_stats(VaultFSStats *stats) {
    pthread_mutex_lock(&s_storage_lock);
    memset(stats, 0, sizeof(VaultFSStats));

    uint64_t total_logical = 0;
    uint64_t total_physical = 0;
    uint64_t total_refs = 0;

    for (uint32_t i = 0; i < s_catalog_count; i++) {
        total_physical += s_catalog[i].disk_size;
        total_logical += (uint64_t)s_catalog[i].original_size * s_catalog[i].ref_count;
        total_refs += s_catalog[i].ref_count;
    }

    stats->unique_blocks = s_catalog_count;
    stats->physical_bytes = total_physical;
    stats->logical_bytes = total_logical;
    stats->total_chunks_referenced = total_refs;
    stats->ransomware_attacks_detected = g_vaultfs.ransomware_attacks_detected;
    stats->files_quarantined = g_vaultfs.files_quarantined;

    if (total_physical > 0) {
        stats->dedup_ratio = (double)total_logical / (double)total_physical;
        if (total_logical > total_physical) {
            stats->space_saved_percent = (1.0 - ((double)total_physical / (double)total_logical)) * 100.0;
        } else {
            stats->space_saved_percent = 0.0;
        }
    } else {
        stats->dedup_ratio = 1.0;
        stats->space_saved_percent = 0.0;
    }

    pthread_mutex_unlock(&s_storage_lock);
}

void storage_save_catalog(void) {
    char path[VAULTFS_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/metadata/catalog.dat", g_vaultfs.backing_dir);

    FILE *f = fopen(path, "wb");
    if (!f) return;

    fwrite(&s_catalog_count, sizeof(uint32_t), 1, f);
    fwrite(s_catalog, sizeof(CatalogEntry), s_catalog_count, f);
    fclose(f);
}

void storage_load_catalog(void) {
    char path[VAULTFS_MAX_PATH + 64];
    snprintf(path, sizeof(path), "%s/metadata/catalog.dat", g_vaultfs.backing_dir);

    FILE *f = fopen(path, "rb");
    if (!f) return;

    if (fread(&s_catalog_count, sizeof(uint32_t), 1, f) == 1) {
        if (s_catalog_count > MAX_CATALOG_ENTRIES) {
            s_catalog_count = MAX_CATALOG_ENTRIES;
        }
        size_t read_items = fread(s_catalog, sizeof(CatalogEntry), s_catalog_count, f);
        (void)read_items;
    }
    fclose(f);
}
