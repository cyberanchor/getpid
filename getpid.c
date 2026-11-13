/**
 * @file getpid.c
 * @brief getpid — Native Linux process inspector (CPU usr/sys, RAM, disk I/O)
 *
 * Reads /proc directly with zero external dependencies.  Designed for
 * Linux kernels 4.x – 6.15.x.  Single-file, static-linkable with glibc/gcc.
 *
 * Features:
 *   - Per-process CPU usage with user/system split (two /proc snapshots)
 *   - Resident memory (VmRSS) display
 *   - Per-process disk I/O rate (read_bytes / write_bytes from /proc/pid/io)
 *   - Thread-level view (-t)
 *   - Focus on a single PID (-p PID)
 *   - Hide kernel threads (-k), detected via the PF_KTHREAD task flag
 *   - Colorized output (green / yellow / red by normalized CPU load)
 *   - Fractional sampling intervals (e.g. -i 0.5)
 *   - Continuous refresh mode (-c)
 *   - Dynamic process list (no hardcoded limits)
 *
 * Build (static):
 *   gcc -O2 -Wall -Wextra -pedantic -std=gnu11 -static -o getpid getpid.c
 *
 * Build (dynamic, smaller binary):
 *   gcc -O2 -Wall -Wextra -pedantic -std=gnu11 -o getpid getpid.c
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <sys/sysinfo.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SNAP_INITIAL_CAP 1024  /**< Initial snapshot capacity; grows via realloc */
#define COMM_LEN          256  /**< Max length of command name                   */
#define PATH_BUF          512  /**< Generic path buffer size                     */

#define PF_KTHREAD 0x00200000  /**< Task flag "I am a kernel thread" (linux/sched.h) */

#define DEFAULT_TOP_N       20
#define DEFAULT_INTERVAL   1.0 /**< seconds between two snapshots                */
#define MIN_INTERVAL      0.01 /**< 10 ms, the same floor as getpid_raw          */
#define MAX_INTERVAL 2147483.0 /**< ~24.8 days, the same ceiling as getpid_raw   */

/* ═══════════════════════════════════════════════════════════════════════════
 *  ANSI color support
 * ═══════════════════════════════════════════════════════════════════════════ */

static int g_use_color = 0;

#define CLR_BOLD    "\033[1m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_RED     "\033[31m"
#define CLR_RESET   "\033[0m"

/**
 * @brief Pick color string based on normalized CPU fraction.
 * @param cpu_pct  CPU% for this process (0 – N*100 for N cores)
 * @param cores    Number of online CPU cores
 * @return ANSI color escape sequence, or "" when color is disabled
 */
static const char *color_for_cpu(double cpu_pct, int cores)
{
    if (!g_use_color)
        return "";
    double frac = cpu_pct / (100.0 * (cores > 0 ? cores : 1));
    if (frac >= 0.80) return CLR_RED;
    if (frac >= 0.30) return CLR_YELLOW;
    return CLR_GREEN;
}

static const char *color_reset(void)
{
    return g_use_color ? CLR_RESET : "";
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Data structures
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Snapshot of a single process (or thread) from /proc.
 *
 * Populated from:
 *   /proc/[pid]/stat    — PID, comm, flags (kernel thread?), utime, stime
 *   /proc/[pid]/status  — VmRSS, Threads, Tgid
 *   /proc/[pid]/io      — read_bytes, write_bytes (disk I/O, not network)
 */
typedef struct {
    int     pid;                /**< PID (or TID in thread mode)              */
    int     tgid;               /**< Thread group leader PID                  */
    char    comm[COMM_LEN];     /**< Short command name from /proc/pid/stat   */

    /* Raw cumulative CPU ticks from /proc/pid/stat fields 14, 15 */
    unsigned long utime;        /**< User-mode CPU ticks                      */
    unsigned long stime;        /**< Kernel-mode CPU ticks                    */

    /* Memory from /proc/pid/status VmRSS line, in kB */
    long    rss_kb;

    /* Disk I/O bytes from /proc/pid/io (NOT network traffic) */
    unsigned long io_read;      /**< read_bytes  — storage reads              */
    unsigned long io_write;     /**< write_bytes — storage writes             */

    /* Computed deltas (populated after diffing two snapshots) */
    double  cpu_usr;            /**< User CPU%   during interval              */
    double  cpu_sys;            /**< System CPU% during interval              */
    double  cpu_total;          /**< Total CPU%  during interval              */
    double  io_read_rate;       /**< Disk read  bytes/sec during interval     */
    double  io_write_rate;      /**< Disk write bytes/sec during interval     */

    int     num_threads;        /**< Thread count from /proc/pid/status       */
    int     is_kernel;          /**< 1 if kernel thread (PF_KTHREAD in stat)  */
    int     is_new;             /**< 1 if not present in previous snapshot    */
} proc_info_t;

/**
 * @brief Dynamically-growing array of proc_info_t.
 *
 * Grows via realloc (doubling) when capacity is reached — no silent
 * data loss regardless of how many processes/threads exist.
 */
typedef struct {
    proc_info_t *entries;
    int          count;
    int          capacity;
} snapshot_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Global options
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct {
    int    top_n;
    double interval;        /**< Fractional seconds (e.g. 0.5)               */
    int    show_threads;
    int    focus_pid;       /**< 0 = all, >0 = specific PID                  */
    int    hide_kernel;
    int    show_io;         /**< Show disk I/O rate columns                   */
    int    continuous;      /**< Loop/refresh mode                            */
} g_opts = {
    .top_n        = DEFAULT_TOP_N,
    .interval     = DEFAULT_INTERVAL,
    .show_threads = 0,
    .focus_pid    = 0,
    .hide_kernel  = 0,
    .show_io      = 1,
    .continuous   = 0,
};

/* Signal flag for clean exit in continuous mode */
static volatile sig_atomic_t g_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  /proc parsing helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Read entire small file into caller-supplied buffer.
 * @return Number of bytes read, or -1 on error (ENOENT, EPERM, etc.)
 *
 * Handles the common /proc race where a process vanishes mid-read.
 * Checks both fread return and ferror for robustness.
 */
static int read_file(const char *path, char *buf, size_t bufsz)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    size_t n = fread(buf, 1, bufsz - 1, fp);
    int err = ferror(fp);
    fclose(fp);

    if (err) return -1;

    buf[n] = '\0';
    return (int)n;
}

/**
 * @brief Parse /proc/[pid]/stat for PID, comm, flags, utime, stime.
 *
 * Layout (kernel 2.6+, unchanged through 6.15.x):
 *   pid (comm) state ppid pgrp session tty_nr tpgid flags
 *   minflt cminflt majflt cmajflt utime stime cutime cstime ...
 *
 * The comm field can contain spaces and parentheses, so we locate
 * the *last* ')' to delimit it reliably.
 *
 * After ')': field[0]=state, field[6]=flags, field[11]=utime, field[12]=stime
 * (0-indexed from the first token after the closing parenthesis).
 *
 * The flags field carries PF_KTHREAD for kernel threads.  Unlike the
 * /proc/[pid]/exe symlink it is readable for every task regardless of
 * who owns it, so the classification does not depend on our privileges.
 *
 * @return 0 on success, -1 if the file is unreadable or the record is
 *         malformed/truncated.
 */
static int parse_proc_stat(const char *path, proc_info_t *info)
{
    char buf[2048];
    if (read_file(path, buf, sizeof(buf)) < 0)
        return -1;

    char *lp = strchr(buf, '(');
    char *rp = strrchr(buf, ')');
    if (!lp || !rp || rp <= lp || rp[1] != ' ')
        return -1;

    info->pid = atoi(buf);

    /* Extract comm (between outermost parentheses) */
    size_t clen = (size_t)(rp - lp - 1);
    if (clen >= COMM_LEN) clen = COMM_LEN - 1;
    memcpy(info->comm, lp + 1, clen);
    info->comm[clen] = '\0';

    /* Walk fields after ') ': flags (index 6), utime (11), stime (12) */
    const char *p = rp + 2; /* skip ") " */
    unsigned long flags = 0;
    int field;
    info->utime = 0;
    info->stime = 0;

    for (field = 0; field < 13; field++) {
        while (*p == ' ') p++;
        if (!*p) break;                 /* record ends early */
        if (field == 6)
            flags = strtoul(p, NULL, 10);
        else if (field == 11)
            info->utime = strtoul(p, NULL, 10);
        else if (field == 12)
            info->stime = strtoul(p, NULL, 10);
        while (*p && *p != ' ') p++;
    }
    if (field < 13)
        return -1;                      /* truncated record: do not trust it */

    info->is_kernel = (flags & PF_KTHREAD) != 0;
    return 0;
}

/**
 * @brief Parse VmRSS, Threads, and Tgid from /proc/[pid]/status.
 *
 * The file is read line by line instead of into one fixed buffer: the
 * "Groups:" line comes before VmRSS and grows with the number of
 * supplementary groups, so a 4 KiB snapshot of the file can end before
 * VmRSS is reached (which used to show such processes with 0K RSS).
 */
static void parse_proc_status(const char *path, proc_info_t *info)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return;

    char iobuf[4096];
    setvbuf(fp, iobuf, _IOFBF, sizeof(iobuf));

    info->rss_kb      = 0;
    info->num_threads = 1;

    char line[256];
    int  at_line_start = 1;     /* fgets returns over-long lines in pieces */
    while (fgets(line, sizeof(line), fp)) {
        if (at_line_start) {
            if      (strncmp(line, "VmRSS:",  6) == 0) info->rss_kb      = strtol(line + 6, NULL, 10);
            else if (strncmp(line, "Threads:", 8) == 0) info->num_threads = (int)strtol(line + 8, NULL, 10);
            else if (strncmp(line, "Tgid:",   5) == 0)  info->tgid       = (int)strtol(line + 5, NULL, 10);
        }
        at_line_start = (strchr(line, '\n') != NULL);
    }
    fclose(fp);
}

/**
 * @brief Parse /proc/[pid]/io for read_bytes and write_bytes.
 *
 * These counters represent *storage* I/O (page cache, filesystem, block
 * layer), NOT network traffic.  The file may be unreadable for processes
 * owned by other users unless we run as root.
 */
static void parse_proc_io(const char *path, proc_info_t *info)
{
    char buf[1024];
    info->io_read  = 0;
    info->io_write = 0;

    if (read_file(path, buf, sizeof(buf)) < 0)
        return;

    char *line = buf;
    while (line && *line) {
        if      (strncmp(line, "read_bytes:",  11) == 0) info->io_read  = strtoul(line + 11, NULL, 10);
        else if (strncmp(line, "write_bytes:", 12) == 0) info->io_write = strtoul(line + 12, NULL, 10);

        line = strchr(line, '\n');
        if (line) line++;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Snapshot collection with dynamic growth
 * ═══════════════════════════════════════════════════════════════════════════ */

static void snapshot_init(snapshot_t *snap)
{
    snap->capacity = SNAP_INITIAL_CAP;
    snap->count    = 0;
    snap->entries  = calloc((size_t)snap->capacity, sizeof(proc_info_t));
    if (!snap->entries) {
        fprintf(stderr, "getpid: out of memory\n");
        exit(1);
    }
}

static void snapshot_free(snapshot_t *snap)
{
    free(snap->entries);
    snap->entries  = NULL;
    snap->count    = 0;
    snap->capacity = 0;
}

/**
 * @brief Ensure snapshot has room for at least one more entry.
 *        Doubles capacity via realloc when full.
 */
static void snapshot_grow(snapshot_t *snap)
{
    if (snap->count < snap->capacity)
        return;

    int new_cap = snap->capacity * 2;
    proc_info_t *p = realloc(snap->entries,
                             (size_t)new_cap * sizeof(proc_info_t));
    if (!p) {
        fprintf(stderr, "getpid: realloc failed at %d entries\n", new_cap);
        exit(1);
    }
    /* Zero the newly allocated portion */
    memset(p + snap->capacity, 0,
           (size_t)(new_cap - snap->capacity) * sizeof(proc_info_t));
    snap->entries  = p;
    snap->capacity = new_cap;
}

/**
 * @brief Scan a single /proc/[pid] (or /proc/[pid]/task/[tid]) entry.
 *
 * Parses stat, status, io.  If any critical file is unreadable (process
 * vanished mid-scan), the entry is silently skipped — this is normal
 * /proc behavior and not an error.
 */
static void scan_one(snapshot_t *snap, const char *base_path, int override_tgid)
{
    char path[PATH_BUF];
    proc_info_t tmp;
    memset(&tmp, 0, sizeof(tmp));

    /* Parse stat first — if it fails, process vanished, skip silently */
    snprintf(path, sizeof(path), "%s/stat", base_path);
    if (parse_proc_stat(path, &tmp) < 0)
        return;

    if (override_tgid > 0)
        tmp.tgid = override_tgid;

    snprintf(path, sizeof(path), "%s/status", base_path);
    parse_proc_status(path, &tmp);

    snprintf(path, sizeof(path), "%s/io", base_path);
    parse_proc_io(path, &tmp);

    /* Commit to snapshot (with dynamic growth) */
    snapshot_grow(snap);
    snap->entries[snap->count] = tmp;
    snap->count++;
}

/**
 * @brief Scan every thread of one process (/proc/[pid]/task/[tid]).
 *
 * @p pid may be any thread ID of the process, not only the group leader:
 * /proc/[tid] resolves for all of them, although readdir("/proc") lists
 * leaders only.
 */
static void scan_tasks(snapshot_t *snap, int pid)
{
    char task_dir[PATH_BUF];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);

    DIR *tdir = opendir(task_dir);
    if (!tdir)
        return;                 /* process vanished (or never existed) */

    struct dirent *tde;
    while ((tde = readdir(tdir)) != NULL) {
        if (!isdigit((unsigned char)tde->d_name[0]))
            continue;
        char tpath[PATH_BUF];
        snprintf(tpath, sizeof(tpath), "/proc/%d/task/%s",
                 pid, tde->d_name);
        scan_one(snap, tpath, pid);
    }
    closedir(tdir);
}

/**
 * @brief Collect a full snapshot of all (or filtered) processes/threads.
 */
static void snapshot_collect(snapshot_t *snap)
{
    /* -p PID: go straight to that process instead of walking all of /proc */
    if (g_opts.focus_pid > 0) {
        scan_tasks(snap, g_opts.focus_pid);
        return;
    }

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("getpid: opendir /proc");
        exit(1);
    }

    struct dirent *de;
    while ((de = readdir(proc_dir)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0]))
            continue;

        int pid = atoi(de->d_name);
        if (pid <= 0) continue;

        if (g_opts.show_threads) {
            scan_tasks(snap, pid);
        } else {
            char ppath[PATH_BUF];
            snprintf(ppath, sizeof(ppath), "/proc/%d", pid);
            scan_one(snap, ppath, 0);
        }
    }
    closedir(proc_dir);
}

/**
 * @brief In -p mode an empty snapshot means the target does not exist
 *        (any more).  Say so and fail instead of printing an empty table
 *        — forever, with -c.
 */
static void require_focus_pid(const snapshot_t *snap)
{
    if (g_opts.focus_pid > 0 && snap->count == 0) {
        fprintf(stderr, "getpid: no such process: %d\n", g_opts.focus_pid);
        exit(1);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Delta computation between two snapshots
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Find a PID/TID in a snapshot via linear scan.
 */
static proc_info_t *snapshot_find(snapshot_t *snap, int pid)
{
    for (int i = 0; i < snap->count; i++) {
        if (snap->entries[i].pid == pid)
            return &snap->entries[i];
    }
    return NULL;
}

/**
 * @brief Compute per-process CPU% and I/O rate by diffing two snapshots.
 *
 * For processes present in both snapshots: delta CPU ticks / elapsed time.
 * For processes only in snap_b (new): CPU and I/O set to 0, marked is_new=1.
 * This avoids the bug where a long-running process that missed snap_a
 * would show its entire accumulated CPU time as if it happened in one interval.
 */
static void compute_deltas(snapshot_t *snap_a, snapshot_t *snap_b,
                           double elapsed_secs)
{
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    if (ticks_per_sec <= 0) ticks_per_sec = 100;

    double tick_to_pct = 100.0 / (elapsed_secs * (double)ticks_per_sec);

    for (int i = 0; i < snap_b->count; i++) {
        proc_info_t *b = &snap_b->entries[i];
        proc_info_t *a = snapshot_find(snap_a, b->pid);

        if (!a) {
            /*
             * Process not in previous snapshot.  Could be:
             *   (a) genuinely new short-lived process
             *   (b) old process missed due to /proc race or permissions
             * Showing accumulated ticks would be misleading in case (b),
             * so we report 0 and mark as [new] in output.
             */
            b->cpu_usr       = 0.0;
            b->cpu_sys       = 0.0;
            b->io_read_rate  = 0.0;
            b->io_write_rate = 0.0;
            b->is_new        = 1;
        } else {
            unsigned long du = (b->utime >= a->utime) ? b->utime - a->utime : 0;
            unsigned long ds = (b->stime >= a->stime) ? b->stime - a->stime : 0;
            b->cpu_usr = (double)du * tick_to_pct;
            b->cpu_sys = (double)ds * tick_to_pct;

            unsigned long dr = (b->io_read  >= a->io_read)  ? b->io_read  - a->io_read  : 0;
            unsigned long dw = (b->io_write >= a->io_write) ? b->io_write - a->io_write : 0;
            b->io_read_rate  = (double)dr / elapsed_secs;
            b->io_write_rate = (double)dw / elapsed_secs;
            b->is_new        = 0;
        }
        b->cpu_total = b->cpu_usr + b->cpu_sys;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Sorting — descending by CPU, then RSS, then PID for stability
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmp_cpu_desc(const void *a, const void *b)
{
    const proc_info_t *pa = (const proc_info_t *)a;
    const proc_info_t *pb = (const proc_info_t *)b;

    /* Primary: CPU descending */
    if (pb->cpu_total > pa->cpu_total) return  1;
    if (pb->cpu_total < pa->cpu_total) return -1;

    /* Secondary: RSS descending */
    if (pb->rss_kb > pa->rss_kb) return  1;
    if (pb->rss_kb < pa->rss_kb) return -1;

    /* Tertiary: PID ascending (deterministic) */
    return pa->pid - pb->pid;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Human-readable formatting helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void fmt_bytes_rate(double bps, char *out, size_t outsz)
{
    if      (bps < 1024.0)                     snprintf(out, outsz, "%6.0f B/s",  bps);
    else if (bps < 1024.0 * 1024.0)            snprintf(out, outsz, "%6.1f KB/s", bps / 1024.0);
    else if (bps < 1024.0 * 1024.0 * 1024.0)   snprintf(out, outsz, "%6.1f MB/s", bps / (1024.0 * 1024.0));
    else                                        snprintf(out, outsz, "%6.2f GB/s", bps / (1024.0 * 1024.0 * 1024.0));
}

static void fmt_mem(long kb, char *out, size_t outsz)
{
    if      (kb < 1024)        snprintf(out, outsz, "%ldK",  kb);
    else if (kb < 1024 * 1024) snprintf(out, outsz, "%.1fM", (double)kb / 1024.0);
    else                       snprintf(out, outsz, "%.2fG", (double)kb / (1024.0 * 1024.0));
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Full command line from /proc/[pid]/cmdline
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Make a process-supplied string safe to print in a table cell.
 *
 * cmdline and comm are fully controlled by the process they belong to.
 * Everything outside printable ASCII is replaced with '?': control bytes
 * (ESC, CR, LF, ...) would otherwise reach the terminal verbatim and let
 * a process recolor or clear the screen, or forge extra table rows.
 */
static void sanitize_text(char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c > 0x7e)
            *s = '?';
    }
}

/**
 * @brief Read /proc/[pid]/cmdline and join NUL-separated args with spaces.
 *        Falls back to [comm] if cmdline is empty (kernel threads, zombies,
 *        processes that wiped their argv).
 */
static void get_full_cmd(int pid, int tgid, const char *comm_fallback,
                         char *out, size_t outsz)
{
    int read_pid = (tgid > 0 && tgid != pid) ? tgid : pid;
    char path[PATH_BUF];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", read_pid);

    char buf[1024];
    int n = read_file(path, buf, sizeof(buf));

    /*
     * Programs that rewrite their title in place (sshd, postgres, nginx...)
     * leave the rest of the argv area filled with NULs or spaces.  Drop
     * that padding, otherwise it becomes trailing blanks and a bogus "...".
     */
    while (n > 0 && (buf[n - 1] == '\0' || buf[n - 1] == ' '))
        n--;

    if (n <= 0) {
        snprintf(out, outsz, "[%s]", comm_fallback);
    } else {
        /* Replace NUL argument separators with spaces */
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\0') buf[i] = ' ';
        }

        size_t len = (size_t)n;
        if (len >= outsz) len = outsz - 1;
        memcpy(out, buf, len);
        out[len] = '\0';
    }

    sanitize_text(out);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Output
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_separator(int width)
{
    for (int i = 0; i < width; i++)
        fputc('-', stdout);
    fputc('\n', stdout);
}

/**
 * @brief Print sorted results.
 *
 * IMPORTANT: top_n counts *displayed* rows, not array indices.
 * Filtered entries (kernel threads when -k is set) do not consume
 * the display quota, so you always get exactly N visible rows
 * (or fewer if there aren't enough matching processes).
 */
static void print_results(snapshot_t *snap, int cores)
{
    /*
     * Aggregate totals.  This has to happen before sorting: the entries are
     * still in /proc scan order, where all threads of a process are adjacent.
     * Threads share one address space, so in thread view every TID reports
     * the RSS of the whole process — count it once per process, not once
     * per thread.
     */
    double total_cpu = 0.0;
    long   total_rss = 0;
    long   group_rss = 0;
    int    group_id  = -1;

    for (int i = 0; i < snap->count; i++) {
        const proc_info_t *e = &snap->entries[i];
        int owner = (e->tgid > 0) ? e->tgid : e->pid;

        if (owner != group_id) {
            total_rss += group_rss;
            group_id   = owner;
            group_rss  = 0;
        }
        if (e->rss_kb > group_rss)
            group_rss = e->rss_kb;

        total_cpu += e->cpu_total;
    }
    total_rss += group_rss;

    qsort(snap->entries, (size_t)snap->count, sizeof(proc_info_t), cmp_cpu_desc);

    char rss_str[32];
    fmt_mem(total_rss, rss_str, sizeof(rss_str));
    printf("\nCPU cores: %d  |  %s: %d  |  Interval: %.1fs  |  "
           "Total CPU: %.1f%%  |  Total RSS: %s\n",
           cores, g_opts.show_threads ? "Threads" : "Processes",
           snap->count, g_opts.interval, total_cpu, rss_str);

    /* Column headers */
    if (g_opts.show_io) {
        printf("\n%s%7s  %-45s  %6s  %6s  %6s  %8s  %12s  %12s%s\n",
               g_use_color ? CLR_BOLD : "",
               g_opts.show_threads ? "TID" : "PID",
               "COMMAND", "USR%", "SYS%", "CPU%", "RSS",
               "IO_RD/s", "IO_WR/s",
               g_use_color ? CLR_RESET : "");
        print_separator(118);
    } else {
        printf("\n%s%7s  %-45s  %6s  %6s  %6s  %8s%s\n",
               g_use_color ? CLR_BOLD : "",
               g_opts.show_threads ? "TID" : "PID",
               "COMMAND", "USR%", "SYS%", "CPU%", "RSS",
               g_use_color ? CLR_RESET : "");
        print_separator(90);
    }

    int displayed = 0;

    for (int i = 0; i < snap->count && displayed < g_opts.top_n; i++) {
        proc_info_t *e = &snap->entries[i];

        /* Filters do NOT count toward the top_n display quota */
        if (g_opts.hide_kernel && e->is_kernel)
            continue;

        char cmd[512];
        get_full_cmd(e->pid, e->tgid, e->comm, cmd, sizeof(cmd));

        /*
         * Truncate command for display.  New processes get a " [new]" tag,
         * so leave room for it: the cell must not exceed 44 characters or
         * the numeric columns of that row shift to the right.
         */
        size_t max_cmd = e->is_new ? 44 - 6 : 44;
        if (strlen(cmd) > max_cmd) {
            memcpy(cmd + max_cmd - 3, "...", 3);
            cmd[max_cmd] = '\0';
        }

        /* Annotate new processes that weren't in previous snapshot */
        if (e->is_new)
            strcat(cmd, " [new]");

        char mem_str[32];
        fmt_mem(e->rss_kb, mem_str, sizeof(mem_str));

        const char *clr = color_for_cpu(e->cpu_total, cores);
        const char *rst = color_reset();

        if (g_opts.show_io) {
            char rd_str[32], wr_str[32];
            fmt_bytes_rate(e->io_read_rate,  rd_str, sizeof(rd_str));
            fmt_bytes_rate(e->io_write_rate, wr_str, sizeof(wr_str));

            printf("%s%7d  %-45s  %6.1f  %6.1f  %6.1f  %8s  %12s  %12s%s\n",
                   clr, e->pid, cmd,
                   e->cpu_usr, e->cpu_sys, e->cpu_total,
                   mem_str, rd_str, wr_str, rst);
        } else {
            printf("%s%7d  %-45s  %6.1f  %6.1f  %6.1f  %8s%s\n",
                   clr, e->pid, cmd,
                   e->cpu_usr, e->cpu_sys, e->cpu_total,
                   mem_str, rst);
        }

        displayed++;
    }

    printf("\n");
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Usage / help
 * ═══════════════════════════════════════════════════════════════════════════ */

static void usage(void)
{
    fprintf(stderr,
        "getpid — native Linux CPU/RAM/IO process inspector\n"
        "\n"
        "Reads /proc directly.  No external dependencies.\n"
        "\n"
        "Usage: getpid [options]\n"
        "\n"
        "Options:\n"
        "  -n, --top N         Show top N processes (default: 20)\n"
        "  -i, --interval SEC  Seconds between snapshots; fractional ok (default: 1.0,\n"
        "                      minimum: 0.01)\n"
        "  -t, --threads       Show individual threads (TID view)\n"
        "  -p, --pid PID       Focus on a single PID (implies -t)\n"
        "  -k, --hide-kernel   Hide kernel threads (PF_KTHREAD flag in /proc/pid/stat)\n"
        "  -I, --no-io         Hide disk I/O rate columns\n"
        "  -c, --continuous    Repeat until Ctrl-C\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Notes:\n"
        "  I/O columns show *disk* (storage) I/O from /proc/pid/io, NOT network.\n"
        "  New processes (not in previous snapshot) show 0%% CPU and [new] tag.\n"
        "\n"
        "Color (when stdout is a TTY):\n"
        "  Green  = CPU < 30%% of one core\n"
        "  Yellow = CPU 30-80%% of one core\n"
        "  Red    = CPU >= 80%% of one core\n"
        "\n"
        "Build:\n"
        "  gcc -O2 -Wall -Wextra -pedantic -std=gnu11 -o getpid getpid.c\n"
        "  gcc -O2 -Wall -Wextra -pedantic -std=gnu11 -static -o getpid getpid.c\n"
        "\n"
        "Supported kernels: Linux 2.6+ through 6.15.x\n"
    );
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Timing helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static double monotonic_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/**
 * @brief Sleep for a fractional number of seconds using nanosleep.
 *        Handles EINTR (signal interruption) gracefully for clean Ctrl-C.
 */
static void precise_sleep(double secs)
{
    struct timespec req;
    req.tv_sec  = (time_t)secs;
    req.tv_nsec = (long)((secs - (double)req.tv_sec) * 1e9);

    while (nanosleep(&req, &req) == -1) {
        if (errno != EINTR) break;
        if (!g_running)     break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Strict option-value parsing (same rules as getpid_raw)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Parse a decimal integer that must fit in an int.
 *
 * Rejects everything atoi() would silently turn into 0 or cut short:
 * "abc", "5x", "", leading blanks, out-of-range values.
 */
static int parse_int_strict(const char *s, int *out)
{
    char *end;

    if (!isdigit((unsigned char)s[0]) && s[0] != '-' && s[0] != '+')
        return 0;

    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < INT_MIN || v > INT_MAX)
        return 0;

    *out = (int)v;
    return 1;
}

/**
 * @brief Parse an interval in seconds: digits with at most one '.'.
 *
 * No sign, exponent, "inf" or "nan" — atof() accepted all of those, and a
 * NaN/infinite interval made nanosleep() fail, turning -c into a busy loop.
 */
static int parse_interval_strict(const char *s, double *out)
{
    int digits = 0, dots = 0;

    for (const char *p = s; *p; p++) {
        if (isdigit((unsigned char)*p))    digits++;
        else if (*p == '.' && dots == 0)   dots++;
        else                               return 0;
    }
    if (digits == 0)
        return 0;

    double v = strtod(s, NULL);
    if (v > MAX_INTERVAL)
        return 0;

    *out = v;
    return 1;
}

static void fail_invalid_number(const char *opt, const char *val)
{
    fprintf(stderr, "Invalid numeric value for %s: %s\n", opt, val);
    usage();
    exit(1);
}

static void fail_invalid_value(const char *opt, const char *msg, const char *val)
{
    fprintf(stderr, "Invalid value for %s: %s %s\n", opt, val, msg);
    usage();
    exit(1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    static struct option longopts[] = {
        {"top",         required_argument, NULL, 'n'},
        {"interval",    required_argument, NULL, 'i'},
        {"threads",     no_argument,       NULL, 't'},
        {"pid",         required_argument, NULL, 'p'},
        {"hide-kernel", no_argument,       NULL, 'k'},
        {"no-io",       no_argument,       NULL, 'I'},
        {"continuous",  no_argument,       NULL, 'c'},
        {"help",        no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "n:i:tp:kIch", longopts, NULL)) != -1) {
        switch (opt) {
        case 'n':
            if (!parse_int_strict(optarg, &g_opts.top_n))
                fail_invalid_number("-n", optarg);
            if (g_opts.top_n <= 0)
                fail_invalid_value("-n", "must be > 0", optarg);
            break;
        case 'i':
            if (!parse_interval_strict(optarg, &g_opts.interval))
                fail_invalid_number("-i", optarg);
            if (g_opts.interval < MIN_INTERVAL)
                fail_invalid_value("-i", "minimum is 10 ms", optarg);
            break;
        case 't': g_opts.show_threads = 1;               break;
        case 'p':
            if (!parse_int_strict(optarg, &g_opts.focus_pid))
                fail_invalid_number("-p", optarg);
            if (g_opts.focus_pid <= 0)
                fail_invalid_value("-p", "pid must be > 0", optarg);
            g_opts.show_threads = 1;
            break;
        case 'k': g_opts.hide_kernel  = 1;               break;
        case 'I': g_opts.show_io      = 0;               break;
        case 'c': g_opts.continuous   = 1;               break;
        case 'h': usage(); return 0;
        default:  usage(); return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        usage();
        return 1;
    }

    g_use_color = isatty(STDOUT_FILENO);

    int cores = get_nprocs();
    if (cores <= 0) cores = 1;

    /* Install signal handlers for clean Ctrl-C exit in continuous mode */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    do {
        snapshot_t snap_a;
        snapshot_init(&snap_a);
        snapshot_collect(&snap_a);
        require_focus_pid(&snap_a);
        double t_a = monotonic_sec();

        precise_sleep(g_opts.interval);
        if (!g_running) {
            snapshot_free(&snap_a);
            break;
        }

        snapshot_t snap_b;
        snapshot_init(&snap_b);
        snapshot_collect(&snap_b);
        require_focus_pid(&snap_b);
        double t_b = monotonic_sec();

        double elapsed = t_b - t_a;
        if (elapsed < 0.01) elapsed = 0.01;

        compute_deltas(&snap_a, &snap_b, elapsed);

        if (g_opts.continuous)
            printf("\033[2J\033[H");

        print_results(&snap_b, cores);

        snapshot_free(&snap_a);
        snapshot_free(&snap_b);

    } while (g_opts.continuous && g_running);

    return 0;
}

