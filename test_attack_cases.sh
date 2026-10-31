#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BACKING_DIR="/tmp/vaultfs_attack_backing"
MOUNT_DIR="/tmp/vaultfs_attack_mount"
PASS="AttackEvaluationSecretPass2026"

echo "======================================================================="
echo "   VAULTFS: TRUNCATE-FIRST & PARTIAL-WRITE ATTACK EVALUATION           "
echo "======================================================================="

make clean all > /dev/null

fusermount3 -u "${MOUNT_DIR}" 2>/dev/null || true
umount "${MOUNT_DIR}" 2>/dev/null || true
rm -rf "${BACKING_DIR}" "${MOUNT_DIR}"
mkdir -p "${BACKING_DIR}" "${MOUNT_DIR}"

echo ""
echo "[Step 1] Mounting VaultFS with Active Defense..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "${PASS}"
sleep 1

# ----------------------------------------------------------------------
# Attack Case 1: Truncate-First (O_TRUNC) Ransomware Attack
# ----------------------------------------------------------------------
echo ""
echo "-----------------------------------------------------------------------"
echo "   [Case 1] TRUNCATE-FIRST ATTACK (O_TRUNC encryption wipe)"
echo "-----------------------------------------------------------------------"
echo "[1.1] Seeding 40 KiB original source code file..."
head -c 40960 /dev/urandom | tr -dc 'a-zA-Z0-9_\n' | head -c 40960 > "${MOUNT_DIR}/critical_driver.c"
ORIG_DRIVER_SHA=$(sha256sum "${MOUNT_DIR}/critical_driver.c" | awk '{print $1}')
ORIG_DRIVER_SIZE=$(stat -c %s "${MOUNT_DIR}/critical_driver.c")
echo "  Original File Size   : ${ORIG_DRIVER_SIZE} bytes"
echo "  Original File SHA-256: ${ORIG_DRIVER_SHA}"

echo ""
echo "[1.2] Attacker executes truncate-first wipe and high-entropy write..."
# Simulate attacker opening with O_TRUNC and writing encrypted payload
cat << 'EOF' > /tmp/run_trunc_attacker.sh
#!/bin/bash
TARGET="$1"
# 1. Truncate to 0 bytes (O_TRUNC)
> "$TARGET"
# 2. Write high-entropy AES/PRNG ciphertext (entropy ~7.99)
openssl rand 40960 > "$TARGET"
EOF
chmod +x /tmp/run_trunc_attacker.sh

/tmp/run_trunc_attacker.sh "${MOUNT_DIR}/critical_driver.c"
rm -f /tmp/run_trunc_attacker.sh
sleep 1

echo ""
echo "[1.3] Checking RansomShield quarantine status..."
./vaultfs-ctl quarantine "${BACKING_DIR}"
./vaultfs-ctl suspects "${BACKING_DIR}"

TRUNC_Q_COUNT=$(./vaultfs-ctl quarantine "${BACKING_DIR}" | grep -c "critical_driver.c" || true)
if [ "$TRUNC_Q_COUNT" -eq 0 ]; then
    echo "ERROR: Truncate-first attack was NOT quarantined!"
    exit 1
fi
echo "[+] SUCCESS: Truncate-first attack intercepted and frozen in Ghost Quarantine Tomb!"

echo ""
echo "[1.4] Unmounting and healing file..."
fusermount3 -u "${MOUNT_DIR}"
sleep 1

./vaultfs-ctl heal "${BACKING_DIR}"

echo ""
echo "[1.5] Remounting and verifying bit-perfect restoration..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "${PASS}"
sleep 1

RESTORED_DRIVER_SHA=$(sha256sum "${MOUNT_DIR}/critical_driver.c" | awk '{print $1}')
RESTORED_DRIVER_SIZE=$(stat -c %s "${MOUNT_DIR}/critical_driver.c")
echo "  Restored File Size   : ${RESTORED_DRIVER_SIZE} bytes"
echo "  Restored File SHA-256: ${RESTORED_DRIVER_SHA}"

if [ "${RESTORED_DRIVER_SHA}" != "${ORIG_DRIVER_SHA}" ] || [ "${RESTORED_DRIVER_SIZE}" != "${ORIG_DRIVER_SIZE}" ]; then
    echo "ERROR: Restored file does not match original pre-truncate state!"
    exit 1
fi
echo "[PASS] Case 1 (Truncate-First Attack): Restored 100% bit-perfect with zero data loss!"

# ----------------------------------------------------------------------
# Attack Case 2: Partial-Write Attack (Sub-block boundary mutation)
# ----------------------------------------------------------------------
echo ""
echo "-----------------------------------------------------------------------"
echo "   [Case 2] PARTIAL-WRITE ATTACK (Sub-block random byte corruption)"
echo "-----------------------------------------------------------------------"
echo "[2.1] Seeding structured telemetry data file (8 KiB, 2 blocks)..."
cat << 'EOF' > "${MOUNT_DIR}/system_telemetry.log"
================================================================================
                    CRITICAL SYSTEM TELEMETRY EVENT LOG                        
================================================================================
[EVENT 001] Power-on self test: PASSED. All sensors calibrated within tolerance.
[EVENT 002] Memory management controller initialized with zero ECC errors.
[EVENT 003] Redundant array online. Storage subsystem integrity verified.
EOF
# Pad to exactly 8192 bytes
truncate -s 8192 "${MOUNT_DIR}/system_telemetry.log"
ORIG_LOG_SHA=$(sha256sum "${MOUNT_DIR}/system_telemetry.log" | awk '{print $1}')
echo "  Original File SHA-256: ${ORIG_LOG_SHA}"

echo ""
echo "[2.2] Attacker overwrites 512 bytes in the middle of block 0 with high entropy..."
python3 -c "
import os
with open('${MOUNT_DIR}/system_telemetry.log', 'r+b') as f:
    f.seek(128)
    f.write(os.urandom(512))
"
sleep 1

echo ""
echo "[2.3] Checking quarantine status..."
./vaultfs-ctl quarantine "${BACKING_DIR}"
PARTIAL_Q_COUNT=$(./vaultfs-ctl quarantine "${BACKING_DIR}" | grep -c "system_telemetry.log" || true)
if [ "$PARTIAL_Q_COUNT" -eq 0 ]; then
    echo "ERROR: Partial-write attack was NOT quarantined!"
    exit 1
fi
echo "[+] SUCCESS: Partial-write attack intercepted and preserved in Ghost Tomb!"

echo ""
echo "[2.4] Unmounting and healing partial-write mutation..."
fusermount3 -u "${MOUNT_DIR}"
sleep 1

./vaultfs-ctl heal "${BACKING_DIR}"

echo ""
echo "[2.5] Remounting and verifying bit-perfect restoration..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "${PASS}"
sleep 1

RESTORED_LOG_SHA=$(sha256sum "${MOUNT_DIR}/system_telemetry.log" | awk '{print $1}')
echo "  Restored File SHA-256: ${RESTORED_LOG_SHA}"

if [ "${RESTORED_LOG_SHA}" != "${ORIG_LOG_SHA}" ]; then
    echo "ERROR: Partial-write restoration hash mismatch!"
    exit 1
fi
echo "[PASS] Case 2 (Partial-Write Attack): Restored 100% bit-perfect with zero data loss!"

fusermount3 -u "${MOUNT_DIR}"
sleep 1
rm -rf "${BACKING_DIR}" "${MOUNT_DIR}"

mkdir -p results
cat << CSVEOL > results/attack_cases.csv
Attack_Type,Target_File,Original_Size,Original_SHA256,Quarantined,Healed_SHA256,Data_Integrity,Status
Truncate_First_O_TRUNC,critical_driver.c,${ORIG_DRIVER_SIZE},${ORIG_DRIVER_SHA},YES,${RESTORED_DRIVER_SHA},100%_Bit_Match,PASS
Partial_Write_Mutation,system_telemetry.log,8192,${ORIG_LOG_SHA},YES,${RESTORED_LOG_SHA},100%_Bit_Match,PASS
CSVEOL

echo ""
echo "======================================================================="
echo "   [ALL PASS] TRUNCATE-FIRST & PARTIAL-WRITE ATTACKS SAFELY NEUTRALIZED"
echo "   Results exported to results/attack_cases.csv"
echo "======================================================================="
