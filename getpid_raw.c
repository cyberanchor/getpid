/**
 * @file getpid_raw.c
 * @brief getpid — Pure-syscall Linux process inspector.  Zero libc dependency.
 *
 * This file implements the same functionality as getpid.c but uses raw
 * Linux syscalls exclusively.  No libc, no crt0, no dynamic linker.
 *
 * Replaces every libc function with:
 *   fopen/fread/fclose   → sys_open + sys_read + sys_close
 *   opendir/readdir      → sys_open + sys_getdents64
 *   printf/snprintf      → custom itoa/utoa/ftoa + sys_write
 *   malloc/realloc/free  → sys_brk arena allocator
 *   sleep/nanosleep      → sys_nanosleep
 *   clock_gettime        → sys_clock_gettime
 *   isatty               → sys_ioctl(TCGETS)
 *   qsort                → custom insertion sort (good enough for ≤8K entries)
 *   getopt               → custom argument parser
 *   signal               → sys_rt_sigaction
 *   get_nprocs            → parse /proc/cpuinfo or /sys/devices/system/cpu
 *   exit                 → sys_exit_group
 *
 * Designed for Linux x86_64, kernels 4.x – 6.15.x.
 *
 * Build:
 * musl-gcc -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -nostdlib -nostartfiles -static -ffreestanding -o getpid_raw getpid_raw.c -lgcc
 *
 */

#define GETPID_VERSION "0.4.0"
#define GETPID_BANNER  "getpid " GETPID_VERSION " — pure-syscall Linux process inspector"

/* ═══════════════════════════════════════════════════════════════════════════
 *  Prevent any libc header inclusion.  We define everything ourselves.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef unsigned long       size_t;
typedef long                ssize_t;
typedef long                off_t;
typedef long                time_t;
typedef int                 pid_t;

#define NULL ((void *)0)

/* ═══════════════════════════════════════════════════════════════════════════
 *  x86_64 Linux syscall numbers (stable ABI since 2.6)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SYS_read            0
#define SYS_write           1
#define SYS_open            2
#define SYS_close           3
#define SYS_brk             12
#define SYS_rt_sigaction    13
#define SYS_ioctl           16
#define SYS_nanosleep       35
#define SYS_exit_group      231
#define SYS_clock_gettime   228
#define SYS_getdents64      217
#define SYS_sysinfo         99

/* open flags */
#define O_RDONLY 0

/* clock ids */
#define CLOCK_MONOTONIC 1

/* ioctl for isatty detection */
#define TCGETS 0x5401

/* signal numbers */
#define SIGINT  2
#define SIGTERM 15
#define SA_RESTORER 0x04000000

/* dirent type */
#define DT_DIR 4

/* Task flag "I am a kernel thread" (linux/sched.h), field 9 of /proc/pid/stat */
#define PF_KTHREAD 0x00200000

/* ═══════════════════════════════════════════════════════════════════════════
 *  Inline syscall wrappers (x86_64 calling convention)
 *
 *  Syscall ABI: rax=nr, args in rdi, rsi, rdx, r10, r8, r9
 *  Return in rax; negative values are -errno.
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline long syscall0(long n)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall1(long n, long a1)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long n, long a1, long a2)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    register long r_a3 __asm__("rdx") = a3;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "r"(r_a3)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall4(long n, long a1, long a2, long a3, long a4)
{
    long ret;
    register long r_a3 __asm__("rdx") = a3;
    register long r_a4 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "r"(r_a3), "r"(r_a4)
                     : "rcx", "r11", "memory");
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Syscall convenience wrappers
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline void sys_exit(int code)
{
    syscall1(SYS_exit_group, code);
    __builtin_unreachable();
}

static inline ssize_t sys_read(int fd, void *buf, size_t count)
{
    return syscall3(SYS_read, fd, (long)buf, (long)count);
}

static inline ssize_t sys_write(int fd, const void *buf, size_t count)
{
    return syscall3(SYS_write, fd, (long)buf, (long)count);
}

static inline int sys_open(const char *path, int flags)
{
    return (int)syscall3(SYS_open, (long)path, flags, 0);
}

static inline int sys_close(int fd)
{
    return (int)syscall1(SYS_close, fd);
}

static inline long sys_getdents64(int fd, void *buf, size_t count)
{
    return syscall3(SYS_getdents64, fd, (long)buf, (long)count);
}

struct timespec {
    time_t tv_sec;
    long   tv_nsec;
};

static inline int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
    return (int)syscall2(SYS_nanosleep, (long)req, (long)rem);
}

static inline int sys_clock_gettime(int clk_id, struct timespec *tp)
{
    return (int)syscall2(SYS_clock_gettime, clk_id, (long)tp);
}

static inline long sys_brk(void *addr)
{
    return syscall1(SYS_brk, (long)addr);
}

static inline int sys_ioctl(int fd, unsigned long request, void *arg)
{
    return (int)syscall3(SYS_ioctl, fd, (long)request, (long)arg);
}

struct kernel_sysinfo {
    long uptime;
    unsigned long loads[3];
    unsigned long totalram;
    unsigned long freeram;
    unsigned long sharedram;
    unsigned long bufferram;
    unsigned long totalswap;
    unsigned long freeswap;
    unsigned short procs;
    unsigned short pad;
    unsigned long totalhigh;
    unsigned long freehigh;
    unsigned int mem_unit;
    char _f[20 - 2 * sizeof(unsigned long) - sizeof(unsigned int)];
};

static inline int sys_sysinfo(struct kernel_sysinfo *info)
{
    return (int)syscall1(SYS_sysinfo, (long)info);
}

/* Signal structures (x86_64 kernel ABI) */
typedef void (*sighandler_t)(int);
typedef struct { unsigned long sig[1]; } kernel_sigset_t;

struct kernel_sigaction {
    sighandler_t sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    kernel_sigset_t sa_mask;
};

/* Restorer trampoline — required by kernel for rt_sigaction on x86_64 */
static void __attribute__((naked)) sa_restorer_trampoline(void)
{
    __asm__ volatile("mov $15, %rax\n\tsyscall"); /* sys_rt_sigreturn = 15 */
}

static inline int sys_rt_sigaction(int sig, const struct kernel_sigaction *act,
                                   struct kernel_sigaction *oldact)
{
    return (int)syscall4(SYS_rt_sigaction, sig, (long)act, (long)oldact, 8);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  String utilities (replacing libc string.h, ctype.h, stdlib.h)
 * ═══════════════════════════════════════════════════════════════════════════ */

static size_t str_len(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

static void *mem_set(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

static void *mem_copy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static int str_cmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int str_ncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static char *str_chr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return (c == 0) ? (char *)s : NULL;
}

static char *str_rchr(const char *s, int c)
{
    const char *last = NULL;
    while (*s) {
        if (*s == (char)c) last = s;
        s++;
    }
    return (char *)last;
}

static int is_digit(int c) { return c >= '0' && c <= '9'; }

/** @brief Simple atoi: parse decimal integer from string. */
static int str_to_int(const char *s)
{
    int neg = 0, val = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;
    while (is_digit(*s)) { val = val * 10 + (*s - '0'); s++; }
    return neg ? -val : val;
}

/** @brief Parse unsigned long from string. */
static unsigned long str_to_ulong(const char *s)
{
    unsigned long val = 0;
    while (*s == ' ' || *s == '\t') s++;
    while (is_digit(*s)) { val = val * 10 + (unsigned long)(*s - '0'); s++; }
    return val;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Output buffer (batched writes to fd 1)
 *
 *  Instead of calling sys_write per character, we buffer up to 8KB
 *  and flush when full or explicitly.  This is our printf replacement.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define OUTBUF_SIZE 8192
static char g_outbuf[OUTBUF_SIZE];
static int  g_outpos = 0;

static void out_flush(void)
{
    int off = 0;
    while (off < g_outpos) {
        ssize_t n = sys_write(1, g_outbuf + off, (size_t)(g_outpos - off));
        if (n <= 0) break; /* unrecoverable write error */
        off += (int)n;
    }
    g_outpos = 0;
}

static void out_char(char c)
{
    if (g_outpos >= OUTBUF_SIZE) out_flush();
    g_outbuf[g_outpos++] = c;
}

static void out_str(const char *s)
{
    while (*s) out_char(*s++);
}

static void out_strn(const char *s, int n)
{
    for (int i = 0; i < n && s[i]; i++)
        out_char(s[i]);
}

/** @brief Output unsigned long as decimal string. */
static void out_ulong(unsigned long v)
{
    char tmp[20];
    int pos = 0;
    if (v == 0) { out_char('0'); return; }
    while (v) { tmp[pos++] = '0' + (char)(v % 10); v /= 10; }
    while (pos > 0) out_char(tmp[--pos]);
}

/** @brief Output signed int as decimal string.  Safe for INT_MIN. */
static void out_int(int v)
{
    if (v < 0) {
        out_char('-');
        /* Cast to long before negating to avoid UB on INT_MIN */
        out_ulong((unsigned long)(-(long)v));
    } else {
        out_ulong((unsigned long)v);
    }
}

/**
 * @brief Output a fixed-point number with 1 decimal place.
 *        val_x10 = value * 10  (e.g. 125 means 12.5)
 *        Safe for LONG_MIN via unsigned arithmetic.
 */
static void out_fixed1(long val_x10)
{
    unsigned long av;
    if (val_x10 < 0) {
        out_char('-');
        av = (unsigned long)(-(val_x10 + 1)) + 1; /* safe negate */
    } else {
        av = (unsigned long)val_x10;
    }
    out_ulong(av / 10);
    out_char('.');
    out_char('0' + (char)(av % 10));
}

/** @brief Right-pad string to width with spaces. */
static void out_str_pad(const char *s, int width)
{
    int len = (int)str_len(s);
    out_str(s);
    for (int i = len; i < width; i++) out_char(' ');
}

/** @brief Right-justify int in field of given width.  Safe for INT_MIN. */
static void out_int_rjust(int v, int width)
{
    char tmp[20];
    int pos = 0, neg = 0;
    unsigned long uv;
    if (v < 0) { neg = 1; uv = (unsigned long)(-(long)v); }
    else { uv = (unsigned long)v; }
    if (uv == 0) tmp[pos++] = '0';
    else while (uv) { tmp[pos++] = '0' + (char)(uv % 10); uv /= 10; }
    if (neg) tmp[pos++] = '-';
    for (int i = pos; i < width; i++) out_char(' ');
    while (pos > 0) out_char(tmp[--pos]);
}

/** @brief Right-justify fixed1 (val_x10) in field of given width.  Safe for LONG_MIN. */
static void out_fixed1_rjust(long val_x10, int width)
{
    char tmp[24];
    int pos = 0;
    unsigned long av;
    if (val_x10 < 0) {
        av = (unsigned long)(-(val_x10 + 1)) + 1;
    } else {
        av = (unsigned long)val_x10;
    }
    int frac = (int)(av % 10);
    unsigned long whole = av / 10;
    char wbuf[20];
    int wlen = 0;
    if (whole == 0) wbuf[wlen++] = '0';
    else while (whole) { wbuf[wlen++] = '0' + (char)(whole % 10); whole /= 10; }
    if (val_x10 < 0) tmp[pos++] = '-';
    for (int i = wlen - 1; i >= 0; i--) tmp[pos++] = wbuf[i];
    tmp[pos++] = '.';
    tmp[pos++] = '0' + (char)frac;
    tmp[pos] = '\0';
    for (int i = pos; i < width; i++) out_char(' ');
    out_strn(tmp, pos);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Stderr output (for warnings/errors)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void err_str(const char *s) {
    size_t len = str_len(s);
    size_t off = 0;
    while (off < len) {
        ssize_t n = sys_write(2, s + off, len - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Arena allocator via sys_brk
 *
 *  Simple bump allocator.  "Free" resets the bump pointer.
 *  Good enough for our two-snapshot lifecycle.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void *g_brk_base  = NULL;
static void *g_brk_cur   = NULL;

static void arena_init(void)
{
    g_brk_base = (void *)sys_brk(NULL);
    g_brk_cur  = g_brk_base;
}

static void *arena_alloc(size_t bytes)
{
    /* Align to 8 bytes */
    bytes = (bytes + 7) & ~(size_t)7;
    void *p = g_brk_cur;
    void *new_end = (char *)g_brk_cur + bytes;
    long result = sys_brk(new_end);
    if ((void *)result < new_end) {
        err_str("getpid: out of memory\n");
        sys_exit(1);
    }
    g_brk_cur = new_end;
    return p;
}

static void arena_reset(void)
{
    /* Reset bump pointer to base, releasing all allocations */
    sys_brk(g_brk_base);
    g_brk_cur = g_brk_base;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Constants and data structures
 * ═══════════════════════════════════════════════════════════════════════════ */

#define COMM_LEN   128
#define PATH_BUF   256
#define FILE_BUF   4096
#define DENTS_BUF  4096

/** @brief Process info record, same semantics as the libc version. */
typedef struct {
    int           pid;
    int           tgid;
    char          comm[COMM_LEN];
    unsigned long utime;
    unsigned long stime;
    long          rss_kb;
    unsigned long io_read;
    unsigned long io_write;
    /* Deltas stored as value * 10 for one-decimal fixed point output */
    long          cpu_usr_x10;    /**< User CPU% * 10   */
    long          cpu_sys_x10;    /**< System CPU% * 10 */
    long          cpu_total_x10;  /**< Total CPU% * 10  */
    long          io_rd_rate;     /**< Disk read  bytes/sec  */
    long          io_wr_rate;     /**< Disk write bytes/sec  */
    int           is_kernel;
    int           is_new;
} proc_info_t;

/** @brief Dynamic array of proc_info_t backed by arena allocator. */
typedef struct {
    proc_info_t *entries;
    int          count;
    int          capacity;
} snapshot_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Global state
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct {
    int top_n;
    int interval_ms;     /**< Interval in milliseconds */
    int show_threads;
    int focus_pid;
    int hide_kernel;
    int show_io;
    int continuous;
} g_opts = {
    .top_n       = 20,
    .interval_ms = 1000,
    .show_threads = 0,
    .focus_pid   = 0,
    .hide_kernel = 0,
    .show_io     = 1,
    .continuous  = 0,
};

static volatile int g_running = 1;
static int g_use_color = 0;
static int g_cores = 1;

static void sighandler(int sig) { (void)sig; g_running = 0; }

/* ═══════════════════════════════════════════════════════════════════════════
 *  /proc file reading (raw syscalls)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Read entire small file via sys_open + sys_read + sys_close.
 * @return bytes read, or -1 on error.
 *
 * Handles EINTR (retry) and distinguishes it from real errors and EOF.
 */
static int read_file(const char *path, char *buf, int bufsz)
{
    int fd = sys_open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t total = 0;
    while (total < bufsz - 1) {
        ssize_t n = sys_read(fd, buf + total, (size_t)(bufsz - 1 - total));
        if (n > 0) {
            total += n;
        } else if (n == 0) {
            break; /* EOF */
        } else {
            /* n < 0: error.  -4 = -EINTR on Linux x86_64 */
            if (n == -4) continue; /* EINTR: retry */
            break; /* real error: return what we have */
        }
    }
    sys_close(fd);
    buf[total] = '\0';
    return (int)total;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Path building helper
 * ═══════════════════════════════════════════════════════════════════════════ */

/** @brief Concatenate base + "/" + suffix into dst. */
static void path_join(char *dst, int dstsz, const char *base, const char *suffix)
{
    int i = 0;
    while (*base && i < dstsz - 2) dst[i++] = *base++;
    dst[i++] = '/';
    while (*suffix && i < dstsz - 1) dst[i++] = *suffix++;
    dst[i] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  /proc parsers
 * ═══════════════════════════════════════════════════════════════════════════ */

static int parse_proc_stat(const char *path, proc_info_t *info)
{
    char buf[2048];
    if (read_file(path, buf, (int)sizeof(buf)) < 0)
        return -1;

    char *lp = str_chr(buf, '(');
    char *rp = str_rchr(buf, ')');
    if (!lp || !rp || rp <= lp || rp[1] != ' ') return -1;

    info->pid = str_to_int(buf);

    size_t clen = (size_t)(rp - lp - 1);
    if (clen >= COMM_LEN) clen = COMM_LEN - 1;
    mem_copy(info->comm, lp + 1, clen);
    info->comm[clen] = '\0';

    /*
     * Fields after ')': state(0) ppid(1) ... flags(6) ... utime(11) stime(12).
     * flags carries PF_KTHREAD for kernel threads; unlike /proc/pid/exe it is
     * readable for every task, whoever owns it.
     */
    const char *p = rp + 2;
    unsigned long flags = 0;
    int field;
    info->utime = 0;
    info->stime = 0;

    for (field = 0; field < 13; field++) {
        while (*p == ' ') p++;
        if (!*p) break;                 /* record ends early */
        if (field == 6) flags = str_to_ulong(p);
        else if (field == 11) info->utime = str_to_ulong(p);
        else if (field == 12) info->stime = str_to_ulong(p);
        while (*p && *p != ' ') p++;
    }
    if (field < 13) return -1;          /* truncated record: do not trust it */

    info->is_kernel = (flags & PF_KTHREAD) != 0;
    return 0;
}

/** @brief Pick the fields we need out of one /proc/pid/status line. */
static void status_line(const char *line, proc_info_t *info)
{
    if      (str_ncmp(line, "VmRSS:", 6) == 0) info->rss_kb = (long)str_to_ulong(line + 6);
    else if (str_ncmp(line, "Tgid:",  5) == 0) info->tgid   = str_to_int(line + 5);
}

/**
 * @brief Parse VmRSS and Tgid from /proc/[pid]/status.
 *
 * The file is consumed in chunks and handled line by line instead of being
 * read once into a fixed buffer: the "Groups:" line comes before VmRSS and
 * grows with the number of supplementary groups, so a single FILE_BUF-sized
 * read can end before VmRSS is reached (such processes showed 0K RSS).
 */
static void parse_proc_status(const char *path, proc_info_t *info)
{
    char buf[FILE_BUF];
    int fd = sys_open(path, O_RDONLY);
    if (fd < 0) return;

    info->rss_kb = 0;

    int have = 0;       /* bytes of an unfinished line kept at buf[0..have) */
    int skipping = 0;   /* inside a line too long to buffer: ignore up to '\n' */
    for (;;) {
        ssize_t n = sys_read(fd, buf + have, (size_t)(FILE_BUF - 1 - have));
        if (n == -4) continue;          /* -EINTR: retry */
        if (n <= 0) break;              /* EOF or real error */
        have += (int)n;
        buf[have] = '\0';

        char *line = buf;
        char *nl;
        while ((nl = str_chr(line, '\n')) != NULL) {
            if (!skipping) status_line(line, info);
            skipping = 0;
            line = nl + 1;
        }

        /* Carry the unfinished tail over to the front of the buffer */
        int tail = have - (int)(line - buf);
        if (tail >= FILE_BUF - 1) {     /* a single line fills the buffer */
            if (!skipping) status_line(line, info);
            skipping = 1;
            tail = 0;
        }
        for (int i = 0; i < tail; i++) buf[i] = line[i];
        have = tail;
    }
    if (have > 0 && !skipping) {        /* last line without a trailing '\n' */
        buf[have] = '\0';
        status_line(buf, info);
    }
    sys_close(fd);
}

static void parse_proc_io(const char *path, proc_info_t *info)
{
    char buf[1024];
    info->io_read  = 0;
    info->io_write = 0;

    if (read_file(path, buf, (int)sizeof(buf)) < 0)
        return;

    char *line = buf;
    while (line && *line) {
        if      (str_ncmp(line, "read_bytes:",  11) == 0) info->io_read  = str_to_ulong(line + 11);
        else if (str_ncmp(line, "write_bytes:", 12) == 0) info->io_write = str_to_ulong(line + 12);

        line = str_chr(line, '\n');
        if (line) line++;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CPU core count from /sys
 * ═══════════════════════════════════════════════════════════════════════════ */

static int detect_cores(void)
{
    /* Read /sys/devices/system/cpu/online, format like "0-7" or "0-3,5-7" */
    char buf[128];
    int n = read_file("/sys/devices/system/cpu/online", buf, (int)sizeof(buf));
    if (n <= 0) return 1;

    /* Parse: count the total number of CPUs across all ranges */
    int total = 0;
    const char *p = buf;
    while (*p) {
        while (*p == ' ') p++;
        if (!is_digit(*p)) break;
        int lo = str_to_int(p);
        while (is_digit(*p)) p++;
        int hi = lo;
        if (*p == '-') {
            p++;
            hi = str_to_int(p);
            while (is_digit(*p)) p++;
        }
        total += hi - lo + 1;
        if (*p == ',') p++;
    }
    return total > 0 ? total : 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Snapshot management
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SNAP_INIT_CAP 1024

/**
 * @brief Initialize snapshot with arena-allocated array.
 *
 * We allocate a large initial chunk.  If more is needed, we
 * arena_alloc a bigger block and copy (poor man's realloc).
 */
static void snap_init(snapshot_t *s)
{
    s->capacity = SNAP_INIT_CAP;
    s->count    = 0;
    s->entries  = (proc_info_t *)arena_alloc((size_t)s->capacity * sizeof(proc_info_t));
    mem_set(s->entries, 0, (size_t)s->capacity * sizeof(proc_info_t));
}

static void snap_grow(snapshot_t *s)
{
    if (s->count < s->capacity) return;

    int new_cap = s->capacity * 2;
    proc_info_t *new_arr = (proc_info_t *)arena_alloc((size_t)new_cap * sizeof(proc_info_t));
    mem_copy(new_arr, s->entries, (size_t)s->count * sizeof(proc_info_t));
    mem_set(new_arr + s->count, 0, (size_t)(new_cap - s->count) * sizeof(proc_info_t));
    /* Old array stays in arena (wasted), but arena resets each cycle */
    s->entries  = new_arr;
    s->capacity = new_cap;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Directory scanning via getdents64
 * ═══════════════════════════════════════════════════════════════════════════ */

/* linux_dirent64 from kernel ABI */
struct linux_dirent64 {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static void scan_one(snapshot_t *snap, const char *base_path, int override_tgid)
{
    char path[PATH_BUF];
    proc_info_t tmp;
    mem_set(&tmp, 0, sizeof(tmp));

    path_join(path, PATH_BUF, base_path, "stat");
    if (parse_proc_stat(path, &tmp) < 0) return;

    if (override_tgid > 0)
        tmp.tgid = override_tgid;

    path_join(path, PATH_BUF, base_path, "status");
    parse_proc_status(path, &tmp);

    path_join(path, PATH_BUF, base_path, "io");
    parse_proc_io(path, &tmp);

    snap_grow(snap);
    snap->entries[snap->count] = tmp;
    snap->count++;
}

/**
 * @brief Iterate directory entries using raw getdents64.
 *        Calls scan_one for each numeric entry.
 */
static void scan_dir_procs(snapshot_t *snap, const char *dirpath, int tgid)
{
    int fd = sys_open(dirpath, O_RDONLY);
    if (fd < 0) return;

    char dents[DENTS_BUF];
    for (;;) {
        long nread = sys_getdents64(fd, dents, sizeof(dents));
        if (nread <= 0) break;

        long pos = 0;
        while (pos < nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(dents + pos);
            if (is_digit(d->d_name[0])) {
                char entry_path[PATH_BUF];
                path_join(entry_path, PATH_BUF, dirpath, d->d_name);

                if (tgid > 0) {
                    /* Thread mode: this is a TID under /proc/pid/task/ */
                    scan_one(snap, entry_path, tgid);
                } else {
                    int pid = str_to_int(d->d_name);
                    if (g_opts.focus_pid > 0 && pid != g_opts.focus_pid) {
                        pos += d->d_reclen;
                        continue;
                    }
                    if (g_opts.show_threads) {
                        char task_path[PATH_BUF];
                        path_join(task_path, PATH_BUF, entry_path, "task");
                        scan_dir_procs(snap, task_path, pid);
                    } else {
                        scan_one(snap, entry_path, 0);
                    }
                }
            }
            pos += d->d_reclen;
        }
    }
    sys_close(fd);
}

static void snapshot_collect(snapshot_t *snap)
{
    scan_dir_procs(snap, "/proc", 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Delta computation
 * ═══════════════════════════════════════════════════════════════════════════ */

static proc_info_t *snap_find(snapshot_t *snap, int pid)
{
    for (int i = 0; i < snap->count; i++) {
        if (snap->entries[i].pid == pid)
            return &snap->entries[i];
    }
    return NULL;
}

/**
 * @brief Compute CPU% and I/O rate.
 *
 * CPU% is stored as fixed-point * 10 (e.g. 125 = 12.5%).
 * This avoids floating-point entirely.
 *
 * Formula: cpu_x10 = delta_ticks * 1000 / (elapsed_ms * CLK_TCK / 1000)
 *        = delta_ticks * 1000000 / (elapsed_ms * CLK_TCK)
 *
 * CLK_TCK = 100 on virtually all Linux systems.
 */
static void compute_deltas(snapshot_t *sa, snapshot_t *sb, int elapsed_ms)
{
    if (elapsed_ms <= 0) elapsed_ms = 1;
    /* ticks_per_sec = 100 (kernel HZ for userspace accounting) */
    long divisor = (long)elapsed_ms * 100; /* elapsed_ms * CLK_TCK */

    for (int i = 0; i < sb->count; i++) {
        proc_info_t *b = &sb->entries[i];
        proc_info_t *a = snap_find(sa, b->pid);

        if (!a) {
            b->cpu_usr_x10   = 0;
            b->cpu_sys_x10   = 0;
            b->io_rd_rate    = 0;
            b->io_wr_rate    = 0;
            b->is_new        = 1;
        } else {
            unsigned long du = (b->utime >= a->utime) ? b->utime - a->utime : 0;
            unsigned long ds = (b->stime >= a->stime) ? b->stime - a->stime : 0;
            /* cpu_x10 = delta * 1000000 / divisor */
            b->cpu_usr_x10 = (long)(du * 1000000UL / (unsigned long)divisor);
            b->cpu_sys_x10 = (long)(ds * 1000000UL / (unsigned long)divisor);

            unsigned long dr = (b->io_read  >= a->io_read)  ? b->io_read  - a->io_read  : 0;
            unsigned long dw = (b->io_write >= a->io_write) ? b->io_write - a->io_write : 0;
            /* bytes/sec = delta_bytes * 1000 / elapsed_ms */
            b->io_rd_rate = (long)(dr * 1000UL / (unsigned long)elapsed_ms);
            b->io_wr_rate = (long)(dw * 1000UL / (unsigned long)elapsed_ms);
            b->is_new = 0;
        }
        b->cpu_total_x10 = b->cpu_usr_x10 + b->cpu_sys_x10;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Sorting — insertion sort (no qsort dependency)
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Compare two proc_info_t: descending CPU, then RSS, then PID.
 * @return >0 if a should come before b (a has higher CPU).
 */
static int proc_cmp(const proc_info_t *a, const proc_info_t *b)
{
    if (a->cpu_total_x10 != b->cpu_total_x10)
        return (a->cpu_total_x10 > b->cpu_total_x10) ? 1 : -1;
    if (a->rss_kb != b->rss_kb)
        return (a->rss_kb > b->rss_kb) ? 1 : -1;
    return (a->pid < b->pid) ? 1 : (a->pid > b->pid) ? -1 : 0;
}

/** @brief Insertion sort — O(n²) but no recursion, no stack, stable. */
static void sort_procs(proc_info_t *arr, int n)
{
    for (int i = 1; i < n; i++) {
        proc_info_t key = arr[i];
        int j = i - 1;
        while (j >= 0 && proc_cmp(&key, &arr[j]) > 0) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Formatting helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/** @brief Format bytes/sec as human-readable into output buffer. */
static void out_io_rate_rjust(long bps, int width)
{
    char tmp[32];
    int pos = 0;

    if (bps < 1024) {
        /* "  NNN B/s" */
        int v = (int)bps;
        char digits[21]; int dp = 0;
        if (v == 0) digits[dp++] = '0';
        else while (v) { digits[dp++] = '0' + (char)(v % 10); v /= 10; }
        while (dp > 0) tmp[pos++] = digits[--dp];
        tmp[pos++] = ' '; tmp[pos++] = 'B'; tmp[pos++] = '/'; tmp[pos++] = 's';
    } else if (bps < 1024 * 1024) {
        long kb_x10 = bps * 10 / 1024;
        long whole = kb_x10 / 10, frac = kb_x10 % 10;
        char digits[21]; int dp = 0;
        long w = whole;
        if (w == 0) digits[dp++] = '0';
        else while (w) { digits[dp++] = '0' + (char)(w % 10); w /= 10; }
        while (dp > 0) tmp[pos++] = digits[--dp];
        tmp[pos++] = '.'; tmp[pos++] = '0' + (char)frac;
        tmp[pos++] = ' '; tmp[pos++] = 'K'; tmp[pos++] = 'B'; tmp[pos++] = '/'; tmp[pos++] = 's';
    } else {
        long mb_x10 = bps * 10 / (1024 * 1024);
        long whole = mb_x10 / 10, frac = mb_x10 % 10;
        char digits[21]; int dp = 0;
        long w = whole;
        if (w == 0) digits[dp++] = '0';
        else while (w) { digits[dp++] = '0' + (char)(w % 10); w /= 10; }
        while (dp > 0) tmp[pos++] = digits[--dp];
        tmp[pos++] = '.'; tmp[pos++] = '0' + (char)frac;
        tmp[pos++] = ' '; tmp[pos++] = 'M'; tmp[pos++] = 'B'; tmp[pos++] = '/'; tmp[pos++] = 's';
    }

    tmp[pos] = '\0';
    for (int i = pos; i < width; i++) out_char(' ');
    out_strn(tmp, pos);
}

/** @brief Format memory (kB) as human-readable and right-justify. */
static void out_mem_rjust(long kb, int width)
{
    char tmp[24];
    int pos = 0;

    if (kb < 1024) {
        long v = kb;
        char digits[21]; int dp = 0;
        if (v == 0) digits[dp++] = '0';
        else while (v) { digits[dp++] = '0' + (char)(v % 10); v /= 10; }
        while (dp > 0) tmp[pos++] = digits[--dp];
        tmp[pos++] = 'K';
    } else if (kb < 1024 * 1024) {
        long mb_x10 = kb * 10 / 1024;
        long whole = mb_x10 / 10, frac = mb_x10 % 10;
        char digits[21]; int dp = 0;
        long w = whole;
        if (w == 0) digits[dp++] = '0';
        else while (w) { digits[dp++] = '0' + (char)(w % 10); w /= 10; }
        while (dp > 0) tmp[pos++] = digits[--dp];
        tmp[pos++] = '.'; tmp[pos++] = '0' + (char)frac;
        tmp[pos++] = 'M';
    } else {
        long gb_x100 = kb * 100 / (1024 * 1024);
        long whole = gb_x100 / 100;
        long frac  = gb_x100 % 100;
        char digits[21]; int dp = 0;
        long w = whole;
        if (w == 0) digits[dp++] = '0';
        else while (w) { digits[dp++] = '0' + (char)(w % 10); w /= 10; }
        while (dp > 0) tmp[pos++] = digits[--dp];
        tmp[pos++] = '.';
        tmp[pos++] = '0' + (char)(frac / 10);
        tmp[pos++] = '0' + (char)(frac % 10);
        tmp[pos++] = 'G';
    }

    tmp[pos] = '\0';
    for (int i = pos; i < width; i++) out_char(' ');
    out_strn(tmp, pos);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Full command line from /proc/[pid]/cmdline
 * ═══════════════════════════════════════════════════════════════════════════ */

static void get_full_cmd(int pid, int tgid, const char *comm_fallback,
                         char *out, int outsz)
{
    int read_pid = (tgid > 0 && tgid != pid) ? tgid : pid;
    char path[PATH_BUF];
    /* Build /proc/<pid>/cmdline */
    char pidstr[16];
    int pi = 0;
    { int v = read_pid; char tmp[16]; int tp = 0;
      if (v == 0) tmp[tp++] = '0';
      else while (v) { tmp[tp++] = '0' + (char)(v % 10); v /= 10; }
      while (tp > 0) pidstr[pi++] = tmp[--tp];
      pidstr[pi] = '\0';
    }
    path_join(path, PATH_BUF, "/proc", pidstr);
    int plen = (int)str_len(path);
    /* Append "/cmdline" */
    const char *suf = "/cmdline";
    for (int i = 0; suf[i]; i++) path[plen + i] = suf[i];
    path[plen + 8] = '\0';

    char buf[512];
    int n = read_file(path, buf, (int)sizeof(buf));
    if (n <= 0) {
        out[0] = '[';
        int i = 0;
        while (comm_fallback[i] && i < outsz - 3) { out[i+1] = comm_fallback[i]; i++; }
        out[i+1] = ']'; out[i+2] = '\0';
        return;
    }

    for (int i = 0; i < n - 1; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    buf[n] = '\0';

    int len = (int)str_len(buf);
    if (len >= outsz) len = outsz - 1;
    mem_copy(out, buf, (size_t)len);
    out[len] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Output: results display
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_results(snapshot_t *snap)
{
    /*
     * Aggregate totals.  This has to happen before sorting: the entries are
     * still in /proc scan order, where all threads of a process are adjacent.
     * Threads share one address space, so in thread view every TID reports
     * the RSS of the whole process — count it once per process, not once
     * per thread.
     */
    long total_cpu_x10 = 0;
    long total_rss = 0;
    long group_rss = 0;
    int  group_id  = -1;
    for (int i = 0; i < snap->count; i++) {
        const proc_info_t *e = &snap->entries[i];
        int owner = (e->tgid > 0) ? e->tgid : e->pid;

        if (owner != group_id) {
            total_rss += group_rss;
            group_id   = owner;
            group_rss  = 0;
        }
        if (e->rss_kb > group_rss) group_rss = e->rss_kb;

        total_cpu_x10 += e->cpu_total_x10;
    }
    total_rss += group_rss;

    sort_procs(snap->entries, snap->count);

    /* Summary line */
    out_str("\nCPU cores: "); out_int(g_cores);
    out_str(g_opts.show_threads ? "  |  Threads: " : "  |  Processes: "); out_int(snap->count);
    out_str("  |  Interval: "); out_fixed1((long)g_opts.interval_ms * 10 / 1000); out_char('s');
    out_str("  |  Total CPU: "); out_fixed1(total_cpu_x10); out_char('%');
    out_str("  |  Total RSS: "); out_mem_rjust(total_rss, 1);
    out_char('\n');

    /* Header */
    out_char('\n');
    if (g_use_color) out_str("\033[1m");

    /* Right-justify the PID/TID header like data rows */
    {
        const char *id_label = g_opts.show_threads ? "TID" : "PID";
        int lbl_len = (int)str_len(id_label);
        for (int pad = lbl_len; pad < 7; pad++) out_char(' ');
        out_str(id_label);
    }
    out_str("  ");
    out_str_pad("COMMAND", 45);
    out_str("  ");
    out_str_pad("USR%", 6);
    out_str("  ");
    out_str_pad("SYS%", 6);
    out_str("  ");
    out_str_pad("CPU%", 6);
    out_str("  ");
    out_str_pad("RSS", 8);

    if (g_opts.show_io) {
        out_str("  ");
        out_str_pad("IO_RD/s", 12);
        out_str("  ");
        out_str_pad("IO_WR/s", 12);
    }

    if (g_use_color) out_str("\033[0m");
    out_char('\n');

    int sep_w = g_opts.show_io ? 118 : 90;
    for (int i = 0; i < sep_w; i++) out_char('-');
    out_char('\n');

    /* Rows — displayed counts toward top_n quota */
    int displayed = 0;
    for (int i = 0; i < snap->count && displayed < g_opts.top_n; i++) {
        proc_info_t *e = &snap->entries[i];

        if (g_opts.hide_kernel && e->is_kernel)
            continue;

        char cmd[256];
        get_full_cmd(e->pid, e->tgid, e->comm, cmd, (int)sizeof(cmd));

        /* Truncate */
        if (str_len(cmd) > 44) {
            cmd[41] = '.'; cmd[42] = '.'; cmd[43] = '.'; cmd[44] = '\0';
        }

        /* [new] tag */
        if (e->is_new) {
            int clen = (int)str_len(cmd);
            if (clen + 6 < (int)sizeof(cmd)) {
                cmd[clen]   = ' '; cmd[clen+1] = '['; cmd[clen+2] = 'n';
                cmd[clen+3] = 'e'; cmd[clen+4] = 'w'; cmd[clen+5] = ']';
                cmd[clen+6] = '\0';
            }
        }

        /* Color */
        if (g_use_color) {
            long frac_x100 = e->cpu_total_x10 * 10 / (g_cores > 0 ? g_cores : 1);
            if (frac_x100 >= 8000)      out_str("\033[31m"); /* red */
            else if (frac_x100 >= 3000) out_str("\033[33m"); /* yellow */
            else                        out_str("\033[32m"); /* green */
        }

        out_int_rjust(e->pid, 7);
        out_str("  ");
        out_str_pad(cmd, 45);
        out_str("  ");
        out_fixed1_rjust(e->cpu_usr_x10, 6);
        out_str("  ");
        out_fixed1_rjust(e->cpu_sys_x10, 6);
        out_str("  ");
        out_fixed1_rjust(e->cpu_total_x10, 6);
        out_str("  ");
        out_mem_rjust(e->rss_kb, 8);

        if (g_opts.show_io) {
            out_str("  ");
            out_io_rate_rjust(e->io_rd_rate, 12);
            out_str("  ");
            out_io_rate_rjust(e->io_wr_rate, 12);
        }

        if (g_use_color) out_str("\033[0m");
        out_char('\n');

        displayed++;
    }

    out_char('\n');
    out_flush();
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Usage
 * ═══════════════════════════════════════════════════════════════════════════ */

static void usage(void)
{
    err_str(
        GETPID_BANNER "\n"
        "\n"
        "Usage: getpid [options]\n"
        "\n"
        "Options:\n"
        "  -n N         Show top N processes (default: 20)\n"
        "  -i SEC       Sampling interval, fractional ok (default: 1.0)\n"
        "  -t           Show individual threads (TID view)\n"
        "  -p PID       Focus on a single PID (implies -t)\n"
        "  -k           Hide kernel threads\n"
        "  -I           Hide disk I/O columns\n"
        "  -c           Continuous refresh (Ctrl-C to stop)\n"
        "  -v           Show version and exit\n"
        "  -h           Show this help\n"
        "\n"
        "I/O columns show *disk* I/O from /proc/pid/io, NOT network.\n"
        "\n"
        "Build:\n"
        "  musl-gcc -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -nostdlib -nostartfiles -static -ffreestanding -o getpid_raw getpid_raw.c -lgcc \n"
        "\n"
    );
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Timing
 * ═══════════════════════════════════════════════════════════════════════════ */

/** @brief Monotonic timestamp in milliseconds. */
static long monotonic_ms(void)
{
    struct timespec ts;
    sys_clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void precise_sleep_ms(int ms)
{
    struct timespec req, rem;
    req.tv_sec  = ms / 1000;
    req.tv_nsec = (long)(ms % 1000) * 1000000L;

    for (;;) {
        int rc = sys_nanosleep(&req, &rem);
        if (rc == 0) break;        /* sleep completed */
        if (!g_running) break;     /* Ctrl-C */
        if (rc == -4) {            /* -EINTR: interrupted by signal */
            req = rem;             /* sleep the remaining time */
            continue;
        }
        break;                     /* other error: give up */
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Argument parsing (custom, no getopt) — strict validation
 * ═══════════════════════════════════════════════════════════════════════════ */

static int is_short_opt_with_value(const char *arg, const char *short_opt, const char **out_val)
{
    int j = 0;
    while (short_opt[j] && arg[j] && short_opt[j] == arg[j]) j++;
    if (short_opt[j] != '\0') return 0;
    if (arg[j] == '\0') return 0;
    *out_val = arg + j;
    return 1;
}

static int is_long_opt_eq(const char *arg, const char *long_opt, const char **out_val)
{
    int j = 0;
    while (long_opt[j] && arg[j] && long_opt[j] == arg[j]) j++;
    if (long_opt[j] != '\0') return 0;
    if (arg[j] != '=') return 0;
    *out_val = arg + j + 1;
    return 1;
}

static void fail_missing_value(const char *opt)
{
    err_str("Option requires a value: "); err_str(opt); err_str("\n");
    usage(); sys_exit(1);
}

static void fail_invalid_number(const char *opt, const char *val)
{
    err_str("Invalid numeric value for "); err_str(opt); err_str(": ");
    err_str(val ? val : "(null)"); err_str("\n"); usage(); sys_exit(1);
}

static void fail_invalid_value(const char *opt, const char *msg, const char *val)
{
    err_str("Invalid value for "); err_str(opt); err_str(": ");
    if (val) err_str(val);
    if (msg) { if (val) err_str(" "); err_str(msg); }
    err_str("\n"); usage(); sys_exit(1);
}

static int parse_int_strict(const char *s, int *out)
{
    /*
     * Parse into unsigned long (no overflow for any digit string that fits).
     * Then apply sign and check int range.
     * Max unsigned digits we need: 10 (2147483648 is 10 digits).
     * Reject anything longer than 10 digits outright.
     */
    int sign = 1, i = 0, ndigits = 0;
    unsigned long v = 0;
    if (!s || !s[0]) return 0;
    if (s[i] == '+') i++; else if (s[i] == '-') { sign = -1; i++; }
    if (!s[i]) return 0;
    for (; s[i]; i++) {
        char c = s[i];
        if (c < '0' || c > '9') return 0;
        ndigits++;
        if (ndigits > 10) return 0; /* cannot be a valid int */
        v = v * 10 + (unsigned long)(c - '0');
    }
    if (ndigits == 0) return 0;
    /* Range check: INT_MIN = -2147483648, INT_MAX = 2147483647 */
    if (sign == 1 && v > 2147483647UL) return 0;
    if (sign == -1 && v > 2147483648UL) return 0;
    *out = (sign == -1) ? -(int)v : (int)v;
    return 1;
}

static int parse_interval_msec_strict(const char *s, int *out)
{
    unsigned long sec = 0, frac = 0, scale = 1;
    int i = 0, saw_digit = 0, saw_dot = 0, sec_digits = 0;
    if (!s || !s[0]) return 0;
    if (s[i] == '+' || s[i] == '-') return 0;
    while (s[i]) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            saw_digit = 1;
            if (!saw_dot) {
                sec_digits++;
                if (sec_digits > 10) return 0; /* prevent overflow */
                sec = sec * 10 + (unsigned long)(c - '0');
                if (sec > 2147483647UL) return 0;
            } else {
                if (scale < 1000) {
                    frac = frac * 10 + (unsigned long)(c - '0');
                    scale *= 10;
                }
                /* digits beyond 3 decimal places: silently ignored */
            }
        } else if (c == '.') {
            if (saw_dot) return 0;
            saw_dot = 1;
        } else {
            return 0;
        }
        i++;
    }
    if (!saw_digit) return 0;
    while (scale < 1000) { frac *= 10; scale *= 10; }
    unsigned long total_ms = sec * 1000UL + frac;
    if (total_ms > 2147483647UL) return 0;
    *out = (int)total_ms;
    return 1;
}

static const char *get_opt_value(int argc, char **argv, int *i, const char *opt, const char *attached)
{
    if (attached) { if (!attached[0]) fail_missing_value(opt); return attached; }
    if (*i + 1 >= argc || argv[*i + 1] == NULL) fail_missing_value(opt);
    (*i)++; return argv[*i];
}

static void parse_args(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        char *a = argv[i];
        const char *attached = 0;
        if (!a) continue;
        if (a[0] != '-') {
            err_str("Unexpected argument: "); err_str(a); err_str("\n");
            usage(); sys_exit(1);
        }
        if (str_cmp(a, "-h") == 0 || str_cmp(a, "--help") == 0) { usage(); sys_exit(0); }
        else if (str_cmp(a, "-v") == 0 || str_cmp(a, "--version") == 0) {
            err_str(GETPID_BANNER "\n"); sys_exit(0);
        }
        else if (str_cmp(a, "-t") == 0 || str_cmp(a, "--threads") == 0) { g_opts.show_threads = 1; }
        else if (str_cmp(a, "-k") == 0 || str_cmp(a, "--hide-kernel") == 0) { g_opts.hide_kernel = 1; }
        else if (str_cmp(a, "-I") == 0 || str_cmp(a, "--no-io") == 0) { g_opts.show_io = 0; }
        else if (str_cmp(a, "-c") == 0 || str_cmp(a, "--continuous") == 0) { g_opts.continuous = 1; }
        else if (str_cmp(a, "-n") == 0 || str_cmp(a, "--top") == 0 ||
                 is_short_opt_with_value(a, "-n", &attached) ||
                 is_long_opt_eq(a, "--top", &attached)) {
            int v; const char *val = get_opt_value(argc, argv, &i, a, attached);
            if (!parse_int_strict(val, &v)) fail_invalid_number(a, val);
            if (v <= 0) fail_invalid_value(a, "must be > 0", val);
            g_opts.top_n = v;
        }
        else if (str_cmp(a, "-i") == 0 || str_cmp(a, "--interval") == 0 ||
                 is_short_opt_with_value(a, "-i", &attached) ||
                 is_long_opt_eq(a, "--interval", &attached)) {
            int v; const char *val = get_opt_value(argc, argv, &i, a, attached);
            if (!parse_interval_msec_strict(val, &v)) fail_invalid_number(a, val);
            if (v < 10) fail_invalid_value(a, "minimum is 10 ms", val);
            g_opts.interval_ms = v;
        }
        else if (str_cmp(a, "-p") == 0 || str_cmp(a, "--pid") == 0 ||
                 is_short_opt_with_value(a, "-p", &attached) ||
                 is_long_opt_eq(a, "--pid", &attached)) {
            int v; const char *val = get_opt_value(argc, argv, &i, a, attached);
            if (!parse_int_strict(val, &v)) fail_invalid_number(a, val);
            if (v <= 0) fail_invalid_value(a, "pid must be > 0", val);
            g_opts.focus_pid = v; g_opts.show_threads = 1;
        }
        else {
            err_str("Unknown option: "); err_str(a); err_str("\n");
            usage(); sys_exit(1);
        }
    }
    if (g_opts.top_n <= 0) g_opts.top_n = 20;
    if (g_opts.interval_ms <= 0) g_opts.interval_ms = 1000;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Entry point — replaces crt0 main()
 *
 *  On x86_64 Linux, the kernel places argc at (%rsp), argv at 8(%rsp).
 *  GCC's function prologue corrupts rsp before our code runs, so we use
 *  a naked asm stub to capture the original stack pointer and pass it
 *  to real_main() as a normal argument via %rdi.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void real_main(long *sp) __attribute__((noreturn, used));

static void real_main(long *sp)
{
    int    argc = (int)sp[0];
    char **argv = (char **)(sp + 1);

    /* Initialize arena allocator */
    arena_init();

    parse_args(argc, argv);

    /* Detect color: ioctl(1, TCGETS, ...) succeeds on a TTY */
    {
        char termios_buf[64];
        g_use_color = (sys_ioctl(1, TCGETS, termios_buf) >= 0) ? 1 : 0;
    }

    g_cores = detect_cores();

    /* Install signal handler for SIGINT/SIGTERM */
    {
        struct kernel_sigaction sa;
        mem_set(&sa, 0, sizeof(sa));
        sa.sa_handler  = sighandler;
        sa.sa_flags    = SA_RESTORER;
        sa.sa_restorer = sa_restorer_trampoline;
        sys_rt_sigaction(SIGINT,  &sa, NULL);
        sys_rt_sigaction(SIGTERM, &sa, NULL);
    }

    do {
        /* Snapshot A */
        snapshot_t snap_a;
        snap_init(&snap_a);
        snapshot_collect(&snap_a);
        long t_a = monotonic_ms();

        /* Wait */
        precise_sleep_ms(g_opts.interval_ms);
        if (!g_running) break;

        /* Snapshot B */
        snapshot_t snap_b;
        snap_init(&snap_b);
        snapshot_collect(&snap_b);
        long t_b = monotonic_ms();

        int elapsed_ms = (int)(t_b - t_a);
        if (elapsed_ms < 1) elapsed_ms = 1;

        compute_deltas(&snap_a, &snap_b, elapsed_ms);

        if (g_opts.continuous)
            out_str("\033[2J\033[H");

        print_results(&snap_b);

        /* Reset arena for next cycle (frees both snapshots) */
        arena_reset();

    } while (g_opts.continuous && g_running);

    sys_exit(0);
    __builtin_unreachable();
}

/**
 * @brief Naked entry point.  Captures pristine rsp before any prologue
 *        and passes it to real_main as first argument (rdi).
 *        Stack must be 16-byte aligned before the call instruction.
 */
__attribute__((naked, noreturn))
void _start(void)
{
    __asm__ volatile(
        "xor  %%rbp, %%rbp\n\t"    /* Mark end of stack frames (ABI) */
        "mov  %%rsp, %%rdi\n\t"    /* Pass original rsp as arg1 */
        "and  $-16, %%rsp\n\t"     /* Align stack to 16 bytes */
        "call real_main\n\t"
        "ud2\n\t"                   /* Should never reach here */
        ::: "memory"
    );
}
