#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BACKING_DIR="/tmp/vaultfs_scoped_backing"
MOUNT_DIR="/tmp/vaultfs_scoped_mount"
PASS="ScopedRollbackSecretPass2026"

echo "======================================================================="
echo "   VAULTFS: PROCESS-ATTRIBUTED WRITES & SCOPED ROLLBACK TEST          "
echo "======================================================================="

# Cleanup old runs
fusermount3 -u "${MOUNT_DIR}" 2>/dev/null || true
umount "${MOUNT_DIR}" 2>/dev/null || true
rm -rf "${BACKING_DIR}" "${MOUNT_DIR}"
mkdir -p "${BACKING_DIR}" "${MOUNT_DIR}"

# Build binaries
make

echo ""
echo "[Step 1] Mounting VaultFS with Process-Attribution and RansomShield..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "${PASS}"
sleep 1

echo ""
echo "[Step 2] Seeding initial files..."
cat << 'EOF' > "${MOUNT_DIR}/victim_doc.txt"
Title: Distributed Consensus in Scalable Storage Systems
Authors: VaultFS Research Group
Abstract: This paper demonstrates process-tree attribution in user-space
filesystems with bounded ring buffers and scoped granular rollbacks.
EOF

cat << 'EOF' > "${MOUNT_DIR}/benign_log.txt"
[2026-10-30 14:00:00] System initialized.
[2026-10-30 14:00:01] Service worker started.
EOF

ORIG_VICTIM_SHA=$(sha256sum "${MOUNT_DIR}/victim_doc.txt" | awk '{print $1}')
echo "Initial victim_doc.txt SHA-256: ${ORIG_VICTIM_SHA}"

echo ""
echo "[Step 3] Launching two concurrent processes..."
echo "  - Process A: Benign process updating benign_log.txt"
echo "  - Process B: Attacker process encrypting victim_doc.txt"

# Create a small script for the benign worker
cat << 'EOF' > /tmp/run_benign.sh
#!/bin/bash
TARGET="$1"
for i in {1..5}; do
    echo "[2026-10-30 14:00:0$i] Benign transaction record #$i processed successfully." >> "$TARGET"
    sleep 0.2
done
echo "FINAL_BENIGN_MARKER_TRANSACTION_COMMITTED" >> "$TARGET"
EOF
chmod +x /tmp/run_benign.sh

# Create a small script for the ransomware simulator
cat << 'EOF' > /tmp/run_attacker.sh
#!/bin/bash
TARGET="$1"
sleep 0.3
# Encrypt victim document with AES-256 high-entropy ciphertext
openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"AttackerRansomKey_PAY_10_BITCOIN" -in "$TARGET" -out /tmp/attacker_cipher.bin
cat /tmp/attacker_cipher.bin > "$TARGET"
rm -f /tmp/attacker_cipher.bin
EOF
chmod +x /tmp/run_attacker.sh

# Run both concurrently in background
/tmp/run_benign.sh "${MOUNT_DIR}/benign_log.txt" &
BENIGN_PID=$!

/tmp/run_attacker.sh "${MOUNT_DIR}/victim_doc.txt" &
ATTACKER_PID=$!

echo "Spawned Benign Worker PID   : ${BENIGN_PID}"
echo "Spawned Attacker Process PID: ${ATTACKER_PID}"

# Wait for both processes to complete
wait ${BENIGN_PID}
wait ${ATTACKER_PID}

echo ""
echo "[Step 4] Checking file states after concurrent execution..."
echo "--- Content of benign_log.txt (tail): ---"
tail -n 3 "${MOUNT_DIR}/benign_log.txt"
echo "--- Content of victim_doc.txt (first 48 hex bytes): ---"
head -c 48 "${MOUNT_DIR}/victim_doc.txt" | od -t x1

echo ""
echo "[Step 5] Inspecting RansomShield suspects and quarantine status..."
./vaultfs-ctl suspects "${BACKING_DIR}"
./vaultfs-ctl quarantine "${BACKING_DIR}"

# Extract flagged PID from suspects or quarantine
FLAGGED_PID=$(./vaultfs-ctl quarantine "${BACKING_DIR}" | grep "victim_doc.txt" | awk -F'|' '{print $6}' | tr -d ' ')
echo "Detected Flagged Tree Root PID: ${FLAGGED_PID}"

if [ -z "${FLAGGED_PID}" ] || [ "${FLAGGED_PID}" = "0" ]; then
    echo "Error: Attacker process was not flagged in quarantine!"
    exit 1
fi

echo ""
echo "[Step 6] Unmounting VaultFS to perform Scoped Rollback..."
fusermount3 -u "${MOUNT_DIR}"
sleep 1

echo ""
echo "[Step 7] Executing Scoped Rollback for compromised tree (PID: ${FLAGGED_PID})..."
./vaultfs-ctl heal --tree "${FLAGGED_PID}" "${BACKING_DIR}"

echo ""
echo "[Step 8] Remounting VaultFS to verify scoped recovery..."
./vaultfs "${BACKING_DIR}" "${MOUNT_DIR}" -p "${PASS}"
sleep 1

RESTORED_VICTIM_SHA=$(sha256sum "${MOUNT_DIR}/victim_doc.txt" | awk '{print $1}')
echo "Restored victim_doc.txt SHA-256: ${RESTORED_VICTIM_SHA}"
echo "Original victim_doc.txt SHA-256: ${ORIG_VICTIM_SHA}"

if [ "${RESTORED_VICTIM_SHA}" != "${ORIG_VICTIM_SHA}" ]; then
    echo "ERROR: Restored victim document hash mismatch!"
    exit 1
fi
echo "[+] Victim file was restored with 100% bit-perfect accuracy!"

echo ""
echo "Verifying benign process changes were completely preserved:"
if ! grep -q "FINAL_BENIGN_MARKER_TRANSACTION_COMMITTED" "${MOUNT_DIR}/benign_log.txt"; then
    echo "ERROR: Benign updates were lost or reverted!"
    exit 1
fi
echo "[+] Benign log contains all updates and was completely untouched by the rollback!"

echo ""
echo "--- Restored victim_doc.txt content: ---"
cat "${MOUNT_DIR}/victim_doc.txt"
echo "----------------------------------------"

fusermount3 -u "${MOUNT_DIR}"
sleep 1
rm -f /tmp/run_benign.sh /tmp/run_attacker.sh
rm -rf "${BACKING_DIR}" "${MOUNT_DIR}"

echo ""
echo "======================================================================="
echo "   [PASS] SCOPED ROLLBACK TEST COMPLETED SUCCESSFULLY!                "
echo "======================================================================="
