#ifndef VAULTFS_CRYPTO_H
#define VAULTFS_CRYPTO_H

#include "vaultfs.h"

void crypto_init(const char *password);
void crypto_sha256(const unsigned char *data, size_t len, char *hex_out);
int  crypto_encrypt(const unsigned char *plaintext, size_t pt_len, const char *chunk_hash,
                    unsigned char **ciphertext_out, size_t *ct_len_out);
int  crypto_decrypt(const unsigned char *ciphertext, size_t ct_len, const char *chunk_hash,
                    unsigned char *plaintext_out, size_t *pt_len_out);

#endif // VAULTFS_CRYPTO_H
