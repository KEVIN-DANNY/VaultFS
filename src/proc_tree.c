#include "proc_tree.h"

#define PROC_CACHE_SIZE 1024
#define PROC_CACHE_TTL_SEC 3

typedef struct {
    pid_t  pid;
    pid_t  tree_root;
    time_t expire_time;
    bool   valid;
} ProcCacheEntry;

static ProcCacheEntry  s_cache[PROC_CACHE_SIZE];
static pthread_mutex_t s_cache_lock = PTHREAD_MUTEX_INITIALIZER;

void proc_tree_init(void) {
    pthread_mutex_lock(&s_cache_lock);
    memset(s_cache, 0, sizeof(s_cache));
    pthread_mutex_unlock(&s_cache_lock);
}

void proc_tree_clear_cache(void) {
    pthread_mutex_lock(&s_cache_lock);
    memset(s_cache, 0, sizeof(s_cache));
    pthread_mutex_unlock(&s_cache_lock);
}

static pid_t lookup_cache(pid_t pid, time_t now) {
    size_t idx = ((size_t)pid) % PROC_CACHE_SIZE;
    if (s_cache[idx].valid && s_cache[idx].pid == pid) {
        if (now <= s_cache[idx].expire_time) {
            return s_cache[idx].tree_root;
        }
    }
    return 0; // Miss or expired
}

static void update_cache(pid_t pid, pid_t tree_root, time_t now) {
    size_t idx = ((size_t)pid) % PROC_CACHE_SIZE;
    s_cache[idx].pid = pid;
    s_cache[idx].tree_root = tree_root;
    s_cache[idx].expire_time = now + PROC_CACHE_TTL_SEC;
    s_cache[idx].valid = true;
}

static bool is_session_boundary(const char *comm) {
    if (!comm) return true;
    const char *boundaries[] = {
        "bash", "sh", "zsh", "dash", "ash", "csh", "tcsh", "fish", "ksh",
        "sshd", "systemd", "init", "login", "tmux", "screen",
        "containerd", "dockerd", "dockerd-current", "containerd-shim",
        "su", "sudo",
        NULL
    };
    for (int i = 0; boundaries[i]; i++) {
        if (strcmp(comm, boundaries[i]) == 0) return true;
    }
    return false;
}

pid_t proc_tree_get_root(pid_t pid) {
    if (pid <= 1) return pid;

    time_t now = time(NULL);

    pthread_mutex_lock(&s_cache_lock);
    pid_t cached = lookup_cache(pid, now);
    if (cached > 0) {
        pthread_mutex_unlock(&s_cache_lock);
        return cached;
    }
    pthread_mutex_unlock(&s_cache_lock);

    // Resolve ppid chain via /proc/<pid>/stat and /proc/<ppid>/comm
    pid_t curr = pid;
    pid_t root = pid;
    int depth = 0;
    const int max_depth = 32;

    while (curr > 1 && depth < max_depth) {
        depth++;
        char stat_path[64];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", (int)curr);

        FILE *f = fopen(stat_path, "r");
        if (!f) {
            // Process may have exited quickly. Use last resolved ancestor.
            break;
        }

        char line[1024];
        if (!fgets(line, sizeof(line), f)) {
            fclose(f);
            break;
        }
        fclose(f);

        // Find the closing parenthesis of executable name (which can contain spaces/parens)
        char *rparen = strrchr(line, ')');
        if (!rparen) break;

        char state = ' ';
        int ppid = 0;
        int pgrp = 0;
        int session = 0;
        if (sscanf(rparen + 1, " %c %d %d %d", &state, &ppid, &pgrp, &session) < 2) {
            break;
        }

        // If curr is a process group leader (e.g. background job, setsid, daemon)
        // and distinct from init/VaultFS, curr is the definitive process tree root
        if (pgrp > 1 && curr == (pid_t)pgrp && pgrp != (int)getpid()) {
            root = curr;
            break;
        }

        // Stop if parent is init (PID 1), kernel (PID 0), or VaultFS itself
        if (ppid <= 1 || ppid == (int)getpid()) {
            root = curr;
            break;
        }

        // Check if parent process is a shell or session boundary
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", ppid);
        FILE *fc = fopen(comm_path, "r");
        if (fc) {
            char pcomm[64];
            if (fgets(pcomm, sizeof(pcomm), fc)) {
                char *nl = strchr(pcomm, '\n');
                if (nl) *nl = '\0';
                if (is_session_boundary(pcomm)) {
                    fclose(fc);
                    root = curr;
                    break;
                }
            }
            fclose(fc);
        }

        root = (pid_t)ppid;
        curr = (pid_t)ppid;
    }

    if (root <= 0) root = pid;

    // Cache the resolved tree root
    pthread_mutex_lock(&s_cache_lock);
    update_cache(pid, root, now);
    pthread_mutex_unlock(&s_cache_lock);

    return root;
}
