#ifndef VAULTFS_ENTROPY_H
#define VAULTFS_ENTROPY_H

#include <stddef.h>
#include <stdbool.h>

#define ENTROPY_RANSOMWARE_THRESHOLD  6.50  // Elevated entropy floor for ciphertext (small and large buffers)
#define ENTROPY_SURGE_DELTA           1.20  // Delta surge indicating encryption attack

/**
 * Calculates the Shannon Entropy of a byte buffer.
 * Returns a value between 0.0 (uniform single byte) and 8.0 (completely random / encrypted).
 */
double entropy_calculate(const unsigned char *data, size_t len);

/**
 * Evaluates whether an incoming write buffer represents an anomalous entropy spike
 * compared to the file's historical baseline.
 */
bool entropy_is_ransomware_suspect(double baseline_entropy, double incoming_entropy);

#endif // VAULTFS_ENTROPY_H
