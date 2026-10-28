#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BACKING_DIR="/tmp/vaultfs_backing"
MOUNT_DIR="/tmp/vaultfs_mount"

echo "======================================================================="
echo "   VAULTFS: RANSOMSHIELD AUTONOMOUS ANTI-RANSOMWARE DEFENSE TEST       "
echo "======================================================================="

# Cleanup old runs
fusermount3 -u "${MOUNT_DIR}" 2>/dev/null || true
umount "${MOUNT_DIR}" 2>/dev/null || true
rm -rf "${BACKING_DIR}" "${MOUNT_DIR}"

mkdir -p "${BACKING_DIR}" "${MOUNT_DIR}"

if [ ! -f ./vaultfs ] || [ ! -f ./vaultfs-ctl ]; then
    echo "Compiling VaultFS with RansomShield Engine..."
    make
fi

echo ""
echo "[Step 1] Mounting VaultFS with RansomShield Active Defense..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "EnterpriseMasterPassword2026"
sleep 1

echo ""
echo "[Step 2] Storing valuable original documents..."
cat << 'EOF' > "${MOUNT_DIR}/thesis_final.txt"
Abstract: This academic paper introduces a novel operating systems storage architecture.
The system guarantees zero-knowledge deduplication and autonomous self-healing.
All data is authenticated, encrypted, and backed by content-addressed storage.
EOF

cat << 'EOF' > "${MOUNT_DIR}/research_data.csv"
patient_id,heart_rate,systolic_bp,blood_oxygen,status
1001,72,120,99,NORMAL
1002,85,135,97,ELEVATED
1003,64,115,99,OPTIMAL
1004,91,142,95,HYPERTENSION
EOF

cat << 'EOF' > "${MOUNT_DIR}/kernel_driver.c"
#include <linux/module.h>
#include <linux/kernel.h>
int init_module(void) {
    printk(KERN_INFO "Critical enterprise module loaded.\n");
    return 0;
}
EOF

# Save checksums of original files
ORIG_THESIS_SHA=$(sha256sum "${MOUNT_DIR}/thesis_final.txt" | awk '{print $1}')
ORIG_CSV_SHA=$(sha256sum "${MOUNT_DIR}/research_data.csv" | awk '{print $1}')
ORIG_DRIVER_SHA=$(sha256sum "${MOUNT_DIR}/kernel_driver.c" | awk '{print $1}')

echo "Verifying original documents before attack:"
echo "--- [thesis_final.txt] --- (SHA256: ${ORIG_THESIS_SHA})"
cat "${MOUNT_DIR}/thesis_final.txt"
echo "--------------------------"

echo ""
echo "[Step 3] Executing Simulated Real-World Ransomware Attack..."
echo "Simulating malware process actively encrypting files with high-entropy ciphertext..."

# Generate high-entropy ciphertext using openssl
for f in "${MOUNT_DIR}"/thesis_final.txt "${MOUNT_DIR}"/research_data.csv "${MOUNT_DIR}"/kernel_driver.c; do
    echo "Malicious process attacking: $f ..."
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"AttackerRansomKey_PAY_10_BITCOIN" -in "$f" -out /tmp/encrypted_temp.bin
    cat /tmp/encrypted_temp.bin > "$f"
    rm -f /tmp/encrypted_temp.bin
done

echo ""
echo "[Step 4] Checking Corrupted File Content (What Ransomware Left Behind):"
echo "--- [thesis_final.txt after attack] ---"
head -c 64 "${MOUNT_DIR}/thesis_final.txt" | od -t x1
echo ""
echo "---------------------------------------"

echo ""
echo "[Step 5] Checking RansomShield Defense Status via vaultfs-ctl:"
./vaultfs-ctl stats "${BACKING_DIR}"
./vaultfs-ctl quarantine "${BACKING_DIR}"

echo ""
echo "[Step 6] Unmounting and Executing Autonomous 0-Second Self-Healing..."
fusermount3 -u "${MOUNT_DIR}"
sleep 1

# Execute self-healing
./vaultfs-ctl heal "${BACKING_DIR}"

echo ""
echo "[Step 7] Remounting VaultFS to verify restored data..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "EnterpriseMasterPassword2026"
sleep 1

echo "Reading restored documents after self-healing:"
echo "--- [thesis_final.txt] ---"
cat "${MOUNT_DIR}/thesis_final.txt"
echo "--------------------------"
echo "--- [research_data.csv] ---"
cat "${MOUNT_DIR}/research_data.csv"
echo "---------------------------"
echo "--- [kernel_driver.c] ---"
cat "${MOUNT_DIR}/kernel_driver.c"
echo "-------------------------"

REST_THESIS_SHA=$(sha256sum "${MOUNT_DIR}/thesis_final.txt" | awk '{print $1}')
REST_CSV_SHA=$(sha256sum "${MOUNT_DIR}/research_data.csv" | awk '{print $1}')
REST_DRIVER_SHA=$(sha256sum "${MOUNT_DIR}/kernel_driver.c" | awk '{print $1}')

echo ""
echo "Cryptographic Integrity Verification:"
echo "Original Thesis SHA: ${ORIG_THESIS_SHA}"
echo "Restored Thesis SHA: ${REST_THESIS_SHA}"
[ "${ORIG_THESIS_SHA}" = "${REST_THESIS_SHA}" ] && echo "  -> [MATCH] thesis_final.txt 100% Bit-Perfect Restoration!"

echo "Original CSV SHA:    ${ORIG_CSV_SHA}"
echo "Restored CSV SHA:    ${REST_CSV_SHA}"
[ "${ORIG_CSV_SHA}" = "${REST_CSV_SHA}" ] && echo "  -> [MATCH] research_data.csv 100% Bit-Perfect Restoration!"

echo "Original Driver SHA: ${ORIG_DRIVER_SHA}"
echo "Restored Driver SHA: ${REST_DRIVER_SHA}"
[ "${ORIG_DRIVER_SHA}" = "${REST_DRIVER_SHA}" ] && echo "  -> [MATCH] kernel_driver.c 100% Bit-Perfect Restoration!"

if [ "${ORIG_THESIS_SHA}" != "${REST_THESIS_SHA}" ] || \
   [ "${ORIG_CSV_SHA}" != "${REST_CSV_SHA}" ] || \
   [ "${ORIG_DRIVER_SHA}" != "${REST_DRIVER_SHA}" ]; then
    echo "ERROR: Self-healing integrity check failed!"
    fusermount3 -u "${MOUNT_DIR}"
    exit 1
fi

# Clean up
fusermount3 -u "${MOUNT_DIR}"

echo ""
echo "======================================================================="
echo "   [PASS] RANSOMSHIELD SUCCESSFULLY NEUTRALIZED ATTACK & RESTORED ALL! "
echo "======================================================================="
