#include "entropy.h"
#include <math.h>
#include <string.h>

double entropy_calculate(const unsigned char *data, size_t len) {
    if (!data || len == 0) return 0.0;

    unsigned int freq[256];
    memset(freq, 0, sizeof(freq));

    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    double inv_len = 1.0 / (double)len;

    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] * inv_len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

bool entropy_is_ransomware_suspect(double baseline_entropy, double incoming_entropy) {
    // 1. High delta jump to elevated entropy (e.g. text/code being encrypted)
    if (incoming_entropy >= ENTROPY_RANSOMWARE_THRESHOLD &&
        (incoming_entropy - baseline_entropy) >= ENTROPY_SURGE_DELTA) {
        return true;
    }
    // 2. High raw entropy over low-to-medium baseline
    if (incoming_entropy >= 7.75 && baseline_entropy < 6.80) {
        return true;
    }
    return false;
}
