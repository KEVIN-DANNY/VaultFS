#!/bin/bash
set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

mkdir -p results

# Clean and rebuild all targets once upfront
make clean all > /dev/null

echo "======================================================================="
echo "       VAULTFS: UNIFIED RESEARCH & ACADEMIC EVALUATION SUITE           "
echo "======================================================================="
echo "Timestamp: $(date -u)"
echo "Kernel   : $(uname -a)"
echo "FUSE     : $(fusermount3 -V 2>&1 | head -n 1)"
echo "OpenSSL  : $(openssl version)"
echo "Compiler : $(gcc --version | head -n 1)"
if command -v git &>/dev/null && [ -d .git ]; then
    GIT_HASH=$(git rev-parse HEAD 2>/dev/null || echo "Unknown")
else
    GIT_HASH="${GIT_COMMIT:-1f1a347c258e05d930cebd5e35e697f552a1c60b}"
fi
echo "Commit   : ${GIT_HASH}"
echo "======================================================================="

# Save environment specifications into results metadata
cat << ENVEOF > results/environment_metadata.txt
VaultFS Research Evaluation Environment:
- Date/Time: $(date -u)
- OS / Kernel: $(uname -a)
- FUSE Library: $(fusermount3 -V 2>&1 | head -n 1)
- OpenSSL Version: $(openssl version)
- GCC Version: $(gcc --version | head -n 1)
- Git Commit: ${GIT_HASH}
ENVEOF

FAILED_SUITES=0

run_test() {
    local test_name="$1"
    local script_cmd="$2"
    local log_file="$3"

    echo ""
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    echo "  RUNNING SUITE: ${test_name}"
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"

    if ${script_cmd} 2>&1 | tee "${log_file}"; then
        echo "[+] ${test_name}: PASSED"
    else
        echo "[-] ${test_name}: FAILED"
        FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
}

# 1. Scoped Rollback Evaluation
run_test "1. Process-Attributed Writes & Scoped Rollback" "./test_scoped_rollback.sh" "results/scoped_rollback.log"

# 2. False Positives & Confusion Matrix Evaluation
run_test "2. False Positives & Multi-Factor Confusion Matrix" "./test_false_positives.sh" "results/false_positives.log"

# 3. Crash Consistency Matrix
run_test "3. Fault-Injection Crash Consistency Matrix" "./test_crash_consistency.sh" "results/crash_consistency.log"

# 4. Truncate-First & Partial-Write Attacks
run_test "4. Truncate-First & Partial-Write Defense" "./test_attack_cases.sh" "results/attack_cases.log"

# 5. Overhead Benchmark
run_test "5. FUSE Passthrough vs VaultFS Overhead Benchmark" "./test_overhead_benchmark.sh" "results/overhead_benchmark.log"

echo ""
echo "======================================================================="
echo "                    RESEARCH SUITE EXECUTION SUMMARY                   "
echo "======================================================================="
if [ "${FAILED_SUITES}" -eq 0 ]; then
    echo "STATUS: ALL 5/5 RESEARCH SUITES COMPLETED WITH 100% SUCCESS!"
    echo "Structured CSV Artifacts Generated in results/:"
    ls -l results/*.csv results/*.txt
    exit 0
else
    echo "STATUS: ${FAILED_SUITES} SUITE(S) FAILED. CHECK LOGS IN results/"
    exit 1
fi
