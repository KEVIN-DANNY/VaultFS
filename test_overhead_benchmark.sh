#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

mkdir -p results

PT_SOURCE="/tmp/pt_bench_source"
PT_MOUNT="/tmp/pt_bench_mount"

VF_BACKING="/tmp/vf_bench_backing"
VF_MOUNT="/tmp/vf_bench_mount"
PASS="BenchmarkPassword2026"

echo "======================================================================="
echo "   VAULTFS VS FUSE PASSTHROUGH: 5-RUN OVERHEAD BENCHMARK EVALUATION    "
echo "======================================================================="

# Compile all binaries
make clean all > /dev/null

# Clean old mounts
fusermount3 -u "${PT_MOUNT}" 2>/dev/null || true
fusermount3 -u "${VF_MOUNT}" 2>/dev/null || true
rm -rf "${PT_SOURCE}" "${PT_MOUNT}" "${VF_BACKING}" "${VF_MOUNT}"
mkdir -p "${PT_SOURCE}" "${PT_MOUNT}" "${VF_BACKING}" "${VF_MOUNT}"

# Initialize CSV file
echo "Filesystem,Run,Operation,Total_MB,Block_KB,Throughput_MBs,P50_us,P95_us" > results/overhead_benchmark.csv

# ---------------------------------------------------------------------
# Phase 1: Benchmark FUSE Passthrough Baseline (5 Runs)
# ---------------------------------------------------------------------
echo ""
echo "[Step 1] Mounting FUSE Passthrough Baseline..."
./tools/passthrough_fs "${PT_SOURCE}" "${PT_MOUNT}" > /tmp/pt_mount.log 2>&1
sleep 1

echo "Executing 5 Benchmark Runs on FUSE Passthrough..."
for r in {1..5}; do
    ./tools/benchmark_io "${PT_MOUNT}" 10 4 $r "FUSE_Passthrough"
    sleep 0.2
done

fusermount3 -u "${PT_MOUNT}"
sleep 1

# ---------------------------------------------------------------------
# Phase 2: Benchmark VaultFS (5 Runs)
# ---------------------------------------------------------------------
echo ""
echo "[Step 2] Mounting VaultFS (Convergent AES-256 + Deduplication + WAL)..."
./vaultfs "${VF_BACKING}" "${VF_MOUNT}" -p "${PASS}" > /tmp/vf_mount.log 2>&1
sleep 1

echo "Executing 5 Benchmark Runs on VaultFS..."
for r in {1..5}; do
    ./tools/benchmark_io "${VF_MOUNT}" 10 4 $r "VaultFS"
    sleep 0.2
done

fusermount3 -u "${VF_MOUNT}"
sleep 1

# ---------------------------------------------------------------------
# Phase 3: Compute Medians and Report Comparison
# ---------------------------------------------------------------------
echo ""
echo "======================================================================="
echo "               BENCHMARK MEDIANS & PERFORMANCE OVERHEAD                "
echo "======================================================================="

python3 - << 'PYEOF'
import csv
import statistics

data = {}
with open('results/overhead_benchmark.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        key = (row['Filesystem'], row['Operation'])
        if key not in data:
            data[key] = {'tp': [], 'p50': [], 'p95': []}
        data[key]['tp'].append(float(row['Throughput_MBs']))
        data[key]['p50'].append(float(row['P50_us']))
        data[key]['p95'].append(float(row['P95_us']))

def get_stats(fs, op):
    d = data.get((fs, op))
    if not d: return 0, 0, 0
    return (statistics.median(d['tp']), statistics.median(d['p50']), statistics.median(d['p95']))

pt_w_tp, pt_w_p50, pt_w_p95 = get_stats('FUSE_Passthrough', 'write')
pt_r_tp, pt_r_p50, pt_r_p95 = get_stats('FUSE_Passthrough', 'read')

vf_w_tp, vf_w_p50, vf_w_p95 = get_stats('VaultFS', 'write')
vf_r_tp, vf_r_p50, vf_r_p95 = get_stats('VaultFS', 'read')

print("+-------------------------+--------------------+--------------------+--------------------+")
print("| Filesystem Engine       | Throughput (MB/s)  | Latency p50 (us)   | Latency p95 (us)   |")
print("+-------------------------+--------------------+--------------------+--------------------+")
print(f"| PT Sequential Write     | {pt_w_tp:18.2f} | {pt_w_p50:18.2f} | {pt_w_p95:18.2f} |")
print(f"| VaultFS Sequential Write| {vf_w_tp:18.2f} | {vf_w_p50:18.2f} | {vf_w_p95:18.2f} |")
w_lat_ovh = ((vf_w_p50 - pt_w_p50) / pt_w_p50 * 100.0) if pt_w_p50 > 0 else 0
print(f"|   -> Write Overhead     |                    | {w_lat_ovh:+17.1f}% |                    |")
print("+-------------------------+--------------------+--------------------+--------------------+")
print(f"| PT Sequential Read      | {pt_r_tp:18.2f} | {pt_r_p50:18.2f} | {pt_r_p95:18.2f} |")
print(f"| VaultFS Sequential Read | {vf_r_tp:18.2f} | {vf_r_p50:18.2f} | {vf_r_p95:18.2f} |")
r_lat_ovh = ((vf_r_p50 - pt_r_p50) / pt_r_p50 * 100.0) if pt_r_p50 > 0 else 0
print(f"|   -> Read Overhead      |                    | {r_lat_ovh:+17.1f}% |                    |")
print("+-------------------------+--------------------+--------------------+--------------------+")

with open('results/overhead_summary.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['Filesystem_Engine', 'Operation', 'Median_Throughput_MBs', 'Median_P50_us', 'Median_P95_us', 'Latency_P50_Overhead_Pct'])
    writer.writerow(['FUSE_Passthrough', 'Sequential_Write', f'{pt_w_tp:.2f}', f'{pt_w_p50:.2f}', f'{pt_w_p95:.2f}', '0.0%'])
    writer.writerow(['VaultFS', 'Sequential_Write', f'{vf_w_tp:.2f}', f'{vf_w_p50:.2f}', f'{vf_w_p95:.2f}', f'{w_lat_ovh:+.1f}%'])
    writer.writerow(['FUSE_Passthrough', 'Sequential_Read', f'{pt_r_tp:.2f}', f'{pt_r_p50:.2f}', f'{pt_r_p95:.2f}', '0.0%'])
    writer.writerow(['VaultFS', 'Sequential_Read', f'{vf_r_tp:.2f}', f'{vf_r_p50:.2f}', f'{vf_r_p95:.2f}', f'{r_lat_ovh:+.1f}%'])
PYEOF

rm -rf "${PT_SOURCE}" "${PT_MOUNT}" "${VF_BACKING}" "${VF_MOUNT}"
echo ""
echo "Benchmark completed successfully. CSV results stored in results/overhead_benchmark.csv and results/overhead_summary.csv"
