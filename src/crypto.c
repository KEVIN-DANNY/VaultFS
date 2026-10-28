#include "crypto.h"

void crypto_init(const char *password) {
    if (!password || strlen(password) == 0) {
        // Default deterministic key if no password specified
        const char *default_pass = "VaultFS_Default_Master_Key_2026";
        SHA256((const unsigned char *)default_pass, strlen(default_pass), g_vaultfs.master_key);
    } else {
        SHA256((const unsigned char *)password, strlen(password), g_vaultfs.master_key);
    }
    g_vaultfs.encrypted = true;
}

void crypto_sha256(const unsigned char *data, size_t len, char *hex_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_out + (i * 2), "%02x", hash[i]);
    }
    hex_out[VAULTFS_HASH_HEX_LEN] = '\0';
}

static void derive_chunk_iv(const char *chunk_hash, unsigned char *iv_out) {
    // Convergent IV derivation: SHA256(chunk_hash + master_key)
    unsigned char combined[VAULTFS_HASH_HEX_LEN + 32];
    memcpy(combined, chunk_hash, VAULTFS_HASH_HEX_LEN);
    memcpy(combined + VAULTFS_HASH_HEX_LEN, g_vaultfs.master_key, 32);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(combined, sizeof(combined), digest);
    // Take first 16 bytes for AES block IV
    memcpy(iv_out, digest, 16);
}

int crypto_encrypt(const unsigned char *plaintext, size_t pt_len, const char *chunk_hash,
                   unsigned char **ciphertext_out, size_t *ct_len_out) {
    unsigned char iv[16];
    derive_chunk_iv(chunk_hash, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Buffer: AES block size is 16 bytes, padding adds up to 16 bytes
    size_t max_out = pt_len + 16;
    unsigned char *ct = malloc(max_out);
    if (!ct) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    int total_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_vaultfs.master_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ct, &len, plaintext, (int)pt_len) != 1) {
        free(ct);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct + total_len, &len) != 1) {
        free(ct);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *ciphertext_out = ct;
    *ct_len_out = (size_t)total_len;
    return 0;
}

int crypto_decrypt(const unsigned char *ciphertext, size_t ct_len, const char *chunk_hash,
                   unsigned char *plaintext_out, size_t *pt_len_out) {
    unsigned char iv[16];
    derive_chunk_iv(chunk_hash, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int total_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_vaultfs.master_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, (int)ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext_out + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *pt_len_out = (size_t)total_len;
    return 0;
}
