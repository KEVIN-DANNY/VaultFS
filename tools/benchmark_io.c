#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

static int compare_doubles(const void *a, const void *b) {
    double diff = (*(const double *)a - *(const double *)b);
    if (diff < 0) return -1;
    if (diff > 0) return 1;
    return 0;
}

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <mount_dir> <total_mb> <block_kb> <run_idx> <fs_name>\n", argv[0]);
        return 1;
    }

    const char *mount_dir = argv[1];
    int total_mb = atoi(argv[2]);
    int block_kb = atoi(argv[3]);
    int run_idx = atoi(argv[4]);
    const char *fs_name = argv[5];

    if (total_mb <= 0) total_mb = 10;
    if (block_kb <= 0) block_kb = 4;

    size_t block_bytes = (size_t)block_kb * 1024;
    size_t total_bytes = (size_t)total_mb * 1024 * 1024;
    size_t num_ops = total_bytes / block_bytes;

    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s/benchmark_testfile.dat", mount_dir);

    unsigned char *buffer = malloc(block_bytes);
    if (!buffer) {
        perror("malloc buffer");
        return 1;
    }
    // Fill buffer with pseudo-random pattern (reproducible seed)
    for (size_t i = 0; i < block_bytes; i++) {
        buffer[i] = (unsigned char)((i * 33 + 7) & 0xFF);
    }

    double *latencies = malloc(num_ops * sizeof(double));
    if (!latencies) {
        perror("malloc latencies");
        free(buffer);
        return 1;
    }

    // --- Benchmark 1: Sequential Write ---
    int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open write");
        free(buffer);
        free(latencies);
        return 1;
    }

    double t_start = get_time_sec();
    for (size_t i = 0; i < num_ops; i++) {
        double op_start = get_time_sec();
        ssize_t w = write(fd, buffer, block_bytes);
        double op_end = get_time_sec();
        if (w < 0 || (size_t)w != block_bytes) {
            perror("write op");
            break;
        }
        latencies[i] = (op_end - op_start) * 1e6; // Microseconds
    }
    fdatasync(fd);
    double t_end = get_time_sec();
    close(fd);

    double total_write_time = t_end - t_start;
    double write_throughput = ((double)total_bytes / (1024.0 * 1024.0)) / total_write_time;

    qsort(latencies, num_ops, sizeof(double), compare_doubles);
    double write_p50 = latencies[(size_t)(num_ops * 0.50)];
    double write_p95 = latencies[(size_t)(num_ops * 0.95)];

    // --- Benchmark 2: Sequential Read ---
    fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        perror("open read");
        free(buffer);
        free(latencies);
        return 1;
    }

    t_start = get_time_sec();
    for (size_t i = 0; i < num_ops; i++) {
        double op_start = get_time_sec();
        ssize_t r = read(fd, buffer, block_bytes);
        double op_end = get_time_sec();
        if (r < 0 || (size_t)r != block_bytes) {
            perror("read op");
            break;
        }
        latencies[i] = (op_end - op_start) * 1e6; // Microseconds
    }
    t_end = get_time_sec();
    close(fd);

    double total_read_time = t_end - t_start;
    double read_throughput = ((double)total_bytes / (1024.0 * 1024.0)) / total_read_time;

    qsort(latencies, num_ops, sizeof(double), compare_doubles);
    double read_p50 = latencies[(size_t)(num_ops * 0.50)];
    double read_p95 = latencies[(size_t)(num_ops * 0.95)];

    unlink(file_path);

    // Output human-readable summary
    printf("[%s | Run #%d] Size: %d MB, Block: %d KB\n", fs_name, run_idx, total_mb, block_kb);
    printf("  Sequential Write: %.2f MB/s | p50: %.2f us | p95: %.2f us\n",
           write_throughput, write_p50, write_p95);
    printf("  Sequential Read : %.2f MB/s | p50: %.2f us | p95: %.2f us\n",
           read_throughput, read_p50, read_p95);

    // Append to CSV
    FILE *fcsv = fopen("results/overhead_benchmark.csv", "a");
    if (fcsv) {
        fprintf(fcsv, "%s,%d,write,%d,%d,%.2f,%.2f,%.2f\n",
                fs_name, run_idx, total_mb, block_kb, write_throughput, write_p50, write_p95);
        fprintf(fcsv, "%s,%d,read,%d,%d,%.2f,%.2f,%.2f\n",
                fs_name, run_idx, total_mb, block_kb, read_throughput, read_p50, read_p95);
        fclose(fcsv);
    }

    free(buffer);
    free(latencies);
    return 0;
}
