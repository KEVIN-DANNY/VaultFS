#ifndef VAULTFS_ENTROPY_H
#define VAULTFS_ENTROPY_H

#include <stddef.h>
#include <stdbool.h>
#include "vaultfs.h"

#define ENTROPY_RANSOMWARE_THRESHOLD  6.50  // Elevated entropy floor for ciphertext (small and large buffers)
#define ENTROPY_SURGE_DELTA           1.20  // Delta surge indicating encryption attack

typedef struct {
    double incoming_entropy;
    double baseline_entropy;
    double entropy_jump;
    double dedup_hit_ratio;
    double replacement_fraction;
    double score;
    bool   is_suspect;
} AnomalyScoreDetails;

/**
 * Calculates the Shannon Entropy of a byte buffer.
 * Returns a value between 0.0 (uniform single byte) and 8.0 (completely random / encrypted).
 */
double entropy_calculate(const unsigned char *data, size_t len);

/**
 * Evaluates whether an incoming write buffer represents an anomalous entropy spike
 * compared to the file's historical baseline (Legacy Entropy-Only Mode).
 */
bool entropy_is_ransomware_suspect(double baseline_entropy, double incoming_entropy);

/**
 * Dedup-Aware Multi-Factor Ransomware Scoring Engine (Feature 2):
 * Combines:
 *  (a) entropy jump vs file's baseline blocks
 *  (b) absolute entropy level
 *  (c) dedup hit ratio (near 0 for fresh ciphertext, near 1 for duplicated files/archives)
 *  (d) fraction of existing blocks replaced in place
 */
AnomalyScoreDetails entropy_evaluate_multifactor(
    double baseline_entropy,
    double incoming_entropy,
    double dedup_hit_ratio,
    double replacement_fraction,
    const RansomShieldConfig *cfg
);

/**
 * Config helper functions: defaults and configuration file loader.
 */
void config_init_defaults(RansomShieldConfig *cfg);
int  config_load_file(const char *path, RansomShieldConfig *cfg);

#endif // VAULTFS_ENTROPY_H
