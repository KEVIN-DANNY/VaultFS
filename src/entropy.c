#include "entropy.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

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

void config_init_defaults(RansomShieldConfig *cfg) {
    if (!cfg) return;
    cfg->mode = SCORING_MODE_DEDUP_AWARE;
    cfg->threshold = 0.50;
    cfg->weight_entropy_jump = 0.35;
    cfg->weight_abs_entropy = 0.25;
    cfg->weight_dedup_novelty = 0.20;
    cfg->weight_replacement = 0.20;
}

static char *trim_whitespace(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

int config_load_file(const char *path, RansomShieldConfig *cfg) {
    if (!path || !cfg) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim_whitespace(line);
        if (*p == '#' || *p == '\0' || *p == ';') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim_whitespace(p);
        char *val = trim_whitespace(eq + 1);

        if (strcasecmp(key, "scoring_mode") == 0 || strcasecmp(key, "mode") == 0) {
            if (strcasecmp(val, "entropy_only") == 0) {
                cfg->mode = SCORING_MODE_ENTROPY_ONLY;
            } else {
                cfg->mode = SCORING_MODE_DEDUP_AWARE;
            }
        } else if (strcasecmp(key, "threshold") == 0) {
            cfg->threshold = atof(val);
        } else if (strcasecmp(key, "weight_entropy_jump") == 0) {
            cfg->weight_entropy_jump = atof(val);
        } else if (strcasecmp(key, "weight_abs_entropy") == 0) {
            cfg->weight_abs_entropy = atof(val);
        } else if (strcasecmp(key, "weight_dedup_novelty") == 0) {
            cfg->weight_dedup_novelty = atof(val);
        } else if (strcasecmp(key, "weight_replacement") == 0) {
            cfg->weight_replacement = atof(val);
        }
    }
    fclose(f);
    return 0;
}

AnomalyScoreDetails entropy_evaluate_multifactor(
    double baseline_entropy,
    double incoming_entropy,
    double dedup_hit_ratio,
    double replacement_fraction,
    const RansomShieldConfig *cfg
) {
    AnomalyScoreDetails res;
    memset(&res, 0, sizeof(res));

    res.incoming_entropy = incoming_entropy;
    res.baseline_entropy = baseline_entropy;
    res.dedup_hit_ratio = dedup_hit_ratio;
    res.replacement_fraction = replacement_fraction;

    RansomShieldConfig default_cfg;
    if (!cfg) {
        config_init_defaults(&default_cfg);
        cfg = &default_cfg;
    }

    if (cfg->mode == SCORING_MODE_ENTROPY_ONLY) {
        // Legacy entropy-only mode
        bool suspect = entropy_is_ransomware_suspect(baseline_entropy, incoming_entropy);
        res.score = suspect ? 1.0 : 0.0;
        res.is_suspect = suspect;
        return res;
    }

    // --- Dedup-Aware Multi-Factor Scoring Engine ---

    // Factor (a): Entropy Jump vs baseline (only evaluated if incoming entropy is elevated)
    double jump = (incoming_entropy > baseline_entropy) ? (incoming_entropy - baseline_entropy) : 0.0;
    res.entropy_jump = jump;
    double s_jump = 0.0;
    if (baseline_entropy > 0.0 && incoming_entropy >= 6.60) {
        s_jump = jump / 4.0;
        if (s_jump > 1.0) s_jump = 1.0;
        if (s_jump < 0.0) s_jump = 0.0;
    }

    // Factor (b): Absolute Entropy
    double s_abs = 0.0;
    if (incoming_entropy >= 6.80) {
        s_abs = (incoming_entropy - 6.80) / 1.20;
        if (s_abs > 1.0) s_abs = 1.0;
    }

    // Factor (c): Dedup Novelty (1 - dedup_hit_ratio)
    // Only contributes to attack score if incoming entropy is elevated towards ciphertext
    double novelty = (incoming_entropy >= 6.60) ? (1.0 - dedup_hit_ratio) : 0.0;
    if (novelty < 0.0) novelty = 0.0;
    if (novelty > 1.0) novelty = 1.0;

    // Factor (d): In-place Replacement Fraction
    double s_replace = replacement_fraction;
    if (s_replace > 1.0) s_replace = 1.0;
    if (s_replace < 0.0) s_replace = 0.0;

    // Combined Score:
    // High-entropy writes with high dedup hits (e.g. copying an existing zip/jpg)
    // are dampened to near zero by dedup novelty and catalog hit damping.
    double raw_score = (cfg->weight_entropy_jump * s_jump) +
                       (cfg->weight_abs_entropy * s_abs) +
                       (cfg->weight_replacement * s_replace) +
                       (cfg->weight_dedup_novelty * novelty);

    // Apply dedup damping multiplier: if chunks already exist in catalog, attack likelihood vanishes
    double dedup_damping = 1.0 - (dedup_hit_ratio * 0.95);
    res.score = raw_score * dedup_damping;

    res.is_suspect = (res.score >= cfg->threshold);
    return res;
}
