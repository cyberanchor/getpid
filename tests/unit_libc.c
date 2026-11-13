/*
 * unit_libc.c — unit tests for the internals of getpid.c.
 *
 * getpid.c is one translation unit of static functions, so the test simply
 * #includes it (with main() renamed) and calls them directly.  The /proc
 * parsers take a path, which lets us feed them fixture files instead of the
 * live /proc.
 *
 * Usage: unit_libc <empty scratch directory>
 *
 * Titles that start with a tag like [B7] are regression tests.  The commit
 * that fixed the bug carries the same tag: git log --grep='\[B7\]'.
 */
#define main getpid_program_main
#include GETPID_SRC             /* "/abs/path/getpid.c", set by the Makefile */
#undef main

#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ───────────────────────────── mini framework ───────────────────────────── */

static int t_tests, t_failed, t_bad;

static void t_fail(int line, const char *fmt, ...)
{
    va_list ap;
    t_bad++;
    printf("        line %d: ", line);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

#define CHECK(cond) \
    do { if (!(cond)) t_fail(__LINE__, "expected: %s", #cond); } while (0)
#define CHECK_INT(got, want) \
    do { long long g_ = (long long)(got), w_ = (long long)(want); \
         if (g_ != w_) t_fail(__LINE__, "%s = %lld, want %lld", #got, g_, w_); } while (0)
#define CHECK_STR(got, want) \
    do { const char *g_ = (got), *w_ = (want); \
         if (strcmp(g_, w_) != 0) t_fail(__LINE__, "%s = \"%s\", want \"%s\"", #got, g_, w_); } while (0)
#define CHECK_NEAR(got, want, tol) \
    do { double g_ = (double)(got), w_ = (double)(want); \
         if (g_ < w_ - (tol) || g_ > w_ + (tol)) \
             t_fail(__LINE__, "%s = %.4f, want %.4f (+-%.4f)", #got, g_, w_, (double)(tol)); } while (0)

#define RUN(fn, title) \
    do { t_tests++; t_bad = 0; fn(); \
         if (t_bad) t_failed++; \
         printf("%s  %s\n", t_bad ? "FAIL" : "ok  ", title); } while (0)

/* ──────────────────────────────── fixtures ──────────────────────────────── */

static char g_dir[512];

/* Path inside the scratch dir.  Rotating buffers: a few may be alive at once. */
static const char *fx(const char *name)
{
    static char bufs[4][700];
    static int  next;
    char *b = bufs[next++ % 4];
    snprintf(b, sizeof(bufs[0]), "%s/%s", g_dir, name);
    return b;
}

static void put_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t len = strlen(data);
    if (fd < 0 || write(fd, data, len) != (ssize_t)len) {
        perror(path);
        exit(2);
    }
    close(fd);
}

/* One /proc/PID/stat record.  Fields after ")": state(0) ppid(1) pgrp(2)
 * session(3) tty(4) tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9)
 * cmajflt(10) utime(11) stime(12) ... num_threads(17) ... starttime(19) */
static const char *stat_rec(int pid, const char *comm, unsigned long flags,
                            unsigned long utime, unsigned long stime,
                            unsigned long long starttime)
{
    static char buf[1024];
    snprintf(buf, sizeof(buf),
        "%d (%s) S 1 %d %d 0 -1 %lu 500 0 3 0 %lu %lu 0 0 20 0 3 0 %llu 10485760 300 "
        "18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        pid, comm, pid, pid, flags, utime, stime, starttime);
    return buf;
}

/* A /proc/PID/status file with `ngroups` supplementary groups. */
static const char *status_rec(int tgid, int pid, long rss_kb, int ngroups)
{
    static char buf[64 * 1024];
    size_t n = 0;
    n += (size_t)snprintf(buf + n, sizeof(buf) - n,
        "Name:\tfixture\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%d\nNgid:\t0\n"
        "Pid:\t%d\nPPid:\t1\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n"
        "Gid:\t1000\t1000\t1000\t1000\nFDSize:\t64\nGroups:\t", tgid, pid);
    for (int i = 0; i < ngroups; i++)
        n += (size_t)snprintf(buf + n, sizeof(buf) - n, "%u ", 4000000000u + (unsigned)i);
    n += (size_t)snprintf(buf + n, sizeof(buf) - n,
        "\nNStgid:\t%d\nNSpid:\t%d\nNSpgid:\t%d\nNSsid:\t%d\n"
        "VmPeak:\t   20480 kB\nVmSize:\t   10240 kB\nVmLck:\t       0 kB\n"
        "VmPin:\t       0 kB\nVmHWM:\t    %ld kB\nVmRSS:\t    %ld kB\n"
        "RssAnon:\t     100 kB\nRssFile:\t     200 kB\nRssShmem:\t       0 kB\n"
        "VmData:\t     300 kB\nVmStk:\t     132 kB\nVmExe:\t      20 kB\n"
        "VmLib:\t    1500 kB\nVmPTE:\t      40 kB\nVmSwap:\t       0 kB\n"
        "Threads:\t3\nSigQ:\t0/3600\nSigPnd:\t0000000000000000\n"
        "voluntary_ctxt_switches:\t10\nnonvoluntary_ctxt_switches:\t2\n",
        tgid, pid, pid, pid, rss_kb, rss_kb);
    return buf;
}

static const char IO_REC[] =
    "rchar: 111111\nwchar: 222222\nsyscr: 33\nsyscw: 44\n"
    "read_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 999\n";

/* Fake /proc/<pid> directory; a NULL argument leaves that file out. */
static const char *make_proc(const char *name, const char *stat_txt,
                             const char *status_txt, const char *io_txt)
{
    static char dir[700], path[800];
    snprintf(dir, sizeof(dir), "%s/%s", g_dir, name);
    mkdir(dir, 0700);
    snprintf(path, sizeof(path), "%s/stat", dir);
    if (stat_txt) put_file(path, stat_txt); else unlink(path);
    snprintf(path, sizeof(path), "%s/status", dir);
    if (status_txt) put_file(path, status_txt); else unlink(path);
    snprintf(path, sizeof(path), "%s/io", dir);
    if (io_txt) put_file(path, io_txt); else unlink(path);
    return dir;
}

#define USER_FLAGS   0x00400000UL               /* PF_RANDOMIZE: ordinary process */
#define KTHREAD_FLAGS (0x00200000UL | 0x00008040UL)  /* PF_KTHREAD | ... */

/* A PID that cannot exist on the live system (above any pid_max). */
#define FAKE_PID 2000000001

/* ───────────────────────────────── tests ────────────────────────────────── */

static void test_read_file(void)
{
    char buf[16];

    CHECK_INT(read_file(fx("does-not-exist"), buf, sizeof(buf)), -1);

    put_file(fx("small"), "hello");
    CHECK_INT(read_file(fx("small"), buf, sizeof(buf)), 5);
    CHECK_STR(buf, "hello");

    /* Longer than the buffer: cut at bufsz-1 and still NUL-terminated */
    put_file(fx("big"), "0123456789abcdefXYZ");
    CHECK_INT(read_file(fx("big"), buf, sizeof(buf)), 15);
    CHECK_STR(buf, "0123456789abcde");
}

static void test_stat_basic(void)
{
    proc_info_t p;
    memset(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(4242, "my-proc", USER_FLAGS, 150, 25, 777));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);
    CHECK_INT(p.pid, 4242);
    CHECK_STR(p.comm, "my-proc");
    CHECK_INT(p.utime, 150);
    CHECK_INT(p.stime, 25);
}

static void test_stat_tricky_comm(void)
{
    /* comm may hold spaces and parentheses; fields must not shift */
    proc_info_t p;
    memset(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(77, "a) (b c) 9 9 9", USER_FLAGS, 31, 32, 1));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);
    CHECK_INT(p.pid, 77);
    CHECK_STR(p.comm, "a) (b c) 9 9 9");
    CHECK_INT(p.utime, 31);
    CHECK_INT(p.stime, 32);

    /* kworker names are longer than TASK_COMM_LEN */
    memset(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(78, "kworker/u16:3-events_unbound_long_description_xxxxxxxxxxxx",
                                  KTHREAD_FLAGS, 1, 2, 1));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);
    CHECK_STR(p.comm, "kworker/u16:3-events_unbound_long_description_xxxxxxxxxxxx");
}

static void test_stat_unreadable_or_garbage(void)
{
    proc_info_t p;
    memset(&p, 0, sizeof(p));
    CHECK_INT(parse_proc_stat(fx("does-not-exist"), &p), -1);

    put_file(fx("stat"), "this is not a stat record\n");
    CHECK_INT(parse_proc_stat(fx("stat"), &p), -1);

    put_file(fx("stat"), "");
    CHECK_INT(parse_proc_stat(fx("stat"), &p), -1);
}

static void test_stat_truncated(void)
{
    proc_info_t p;

    /* Leave a complete record behind in the parser's stack buffer first */
    memset(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(5, "full", USER_FLAGS, 4242, 4343, 1));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);

    /* Nothing after the comm: the parser must not walk past the terminator
     * (and pick up the stale utime/stime of the previous record) */
    memset(&p, 0, sizeof(p));
    put_file(fx("stat"), "7 (x)");
    CHECK_INT(parse_proc_stat(fx("stat"), &p), -1);
    CHECK_INT(p.utime, 0);
    CHECK_INT(p.stime, 0);

    /* Record that stops before utime/stime */
    memset(&p, 0, sizeof(p));
    put_file(fx("stat"), "7 (x) S 1 7 7 0 -1 4194304 500\n");
    CHECK_INT(parse_proc_stat(fx("stat"), &p), -1);
}

static void test_scan_one_fields(void)
{
    snapshot_t s;
    snapshot_init(&s);
    scan_one(&s, make_proc("p1", stat_rec(FAKE_PID, "fixture", USER_FLAGS, 150, 25, 777),
                           status_rec(FAKE_PID, FAKE_PID, 5120, 3), IO_REC), 0);
    CHECK_INT(s.count, 1);
    if (s.count == 1) {
        proc_info_t *e = &s.entries[0];
        CHECK_INT(e->pid, FAKE_PID);
        CHECK_STR(e->comm, "fixture");
        CHECK_INT(e->utime, 150);
        CHECK_INT(e->stime, 25);
        CHECK_INT(e->rss_kb, 5120);
        CHECK_INT(e->io_read, 4096);     /* not rchar */
        CHECK_INT(e->io_write, 8192);    /* not wchar / cancelled_write_bytes */
    }
    snapshot_free(&s);
}

static void test_scan_one_missing_files(void)
{
    snapshot_t s;
    snapshot_init(&s);

    /* No io file (other user's process): entry is kept, I/O is zero */
    scan_one(&s, make_proc("p2", stat_rec(FAKE_PID, "x", USER_FLAGS, 1, 2, 3),
                           status_rec(FAKE_PID, FAKE_PID, 64, 1), NULL), 0);
    CHECK_INT(s.count, 1);
    if (s.count == 1) {
        CHECK_INT(s.entries[0].io_read, 0);
        CHECK_INT(s.entries[0].io_write, 0);
        CHECK_INT(s.entries[0].rss_kb, 64);
    }

    /* No status file (kernel thread-like): RSS is zero */
    scan_one(&s, make_proc("p3", stat_rec(FAKE_PID, "x", USER_FLAGS, 1, 2, 3), NULL, IO_REC), 0);
    CHECK_INT(s.count, 2);
    if (s.count == 2)
        CHECK_INT(s.entries[1].rss_kb, 0);

    /* No stat file (process vanished): nothing is recorded */
    scan_one(&s, make_proc("p4", NULL, status_rec(1, 1, 1, 1), IO_REC), 0);
    CHECK_INT(s.count, 2);

    snapshot_free(&s);
}

static void test_scan_one_thread_tgid(void)
{
    /* A thread: stat carries the TID, status the owning process */
    snapshot_t s;
    snapshot_init(&s);
    scan_one(&s, make_proc("t1", stat_rec(FAKE_PID + 5, "thr", USER_FLAGS, 9, 8, 7),
                           status_rec(FAKE_PID, FAKE_PID + 5, 256, 1), IO_REC), FAKE_PID);
    CHECK_INT(s.count, 1);
    if (s.count == 1) {
        CHECK_INT(s.entries[0].pid, FAKE_PID + 5);
        CHECK_INT(s.entries[0].tgid, FAKE_PID);
    }
    snapshot_free(&s);
}

static void test_status_long_groups(void)
{
    /* ~9 KiB "Groups:" line in front of VmRSS (user in 800 groups) */
    snapshot_t s;
    snapshot_init(&s);
    scan_one(&s, make_proc("p5", stat_rec(FAKE_PID, "many-groups", USER_FLAGS, 1, 2, 3),
                           status_rec(FAKE_PID, FAKE_PID, 5120, 800), IO_REC), 0);
    CHECK_INT(s.count, 1);
    if (s.count == 1) {
        CHECK_INT(s.entries[0].rss_kb, 5120);
        CHECK_INT(s.entries[0].tgid, FAKE_PID);
    }
    snapshot_free(&s);
}

static void test_kernel_thread_flag(void)
{
    /* The verdict must come from the task's own flags, not from whether we
     * happen to be allowed to resolve /proc/PID/exe */
    snapshot_t s;
    snapshot_init(&s);
    scan_one(&s, make_proc("k1", stat_rec(FAKE_PID, "kworker/0:1", KTHREAD_FLAGS, 0, 5, 9),
                           NULL, NULL), 0);
    scan_one(&s, make_proc("u1", stat_rec(FAKE_PID + 1, "daemon", USER_FLAGS, 3, 5, 9),
                           status_rec(FAKE_PID + 1, FAKE_PID + 1, 900, 1), NULL), 0);
    CHECK_INT(s.count, 2);
    if (s.count == 2) {
        CHECK_INT(s.entries[0].is_kernel, 1);
        CHECK_INT(s.entries[1].is_kernel, 0);
    }
    snapshot_free(&s);
}

static void test_snapshot_growth(void)
{
    /* More entries than SNAP_INITIAL_CAP: the array must grow, not drop */
    snapshot_t s;
    const char *dir = make_proc("g1", stat_rec(FAKE_PID, "grow", USER_FLAGS, 11, 22, 33),
                                status_rec(FAKE_PID, FAKE_PID, 128, 1), IO_REC);
    snapshot_init(&s);
    for (int i = 0; i < 2500; i++)
        scan_one(&s, dir, 0);
    CHECK_INT(s.count, 2500);
    CHECK(s.capacity >= 2500);

    int intact = 1;
    for (int i = 0; i < s.count; i++)
        if (s.entries[i].pid != FAKE_PID || s.entries[i].utime != 11 || s.entries[i].rss_kb != 128)
            intact = 0;
    CHECK(intact);
    snapshot_free(&s);
}

static void fill(proc_info_t *e, int pid, unsigned long ut, unsigned long st,
                 unsigned long rd, unsigned long wr)
{
    memset(e, 0, sizeof(*e));
    e->pid = pid;
    e->utime = ut;
    e->stime = st;
    e->io_read = rd;
    e->io_write = wr;
}

static void test_deltas(void)
{
    snapshot_t a, b;
    double tck = (double)sysconf(_SC_CLK_TCK);
    snapshot_init(&a);
    snapshot_init(&b);

    fill(&a.entries[0], 10, 100, 50, 1000, 5000);
    fill(&a.entries[1], 11, 900, 900, 7000, 7000);
    a.count = 2;

    fill(&b.entries[0], 10, 150, 60, 3048, 5000);   /* +50 usr, +10 sys, +2048 B read */
    fill(&b.entries[1], 11, 800, 900, 6000, 9000);  /* counters went backwards         */
    fill(&b.entries[2], 12, 99999, 99999, 1 << 20, 1 << 20);  /* not in snapshot A      */
    b.count = 3;

    compute_deltas(&a, &b, 0.5);

    CHECK_NEAR(b.entries[0].cpu_usr,   50.0 * 100.0 / (0.5 * tck), 0.001);
    CHECK_NEAR(b.entries[0].cpu_sys,   10.0 * 100.0 / (0.5 * tck), 0.001);
    CHECK_NEAR(b.entries[0].cpu_total, 60.0 * 100.0 / (0.5 * tck), 0.001);
    CHECK_NEAR(b.entries[0].io_read_rate, 4096.0, 0.001);
    CHECK_NEAR(b.entries[0].io_write_rate, 0.0, 0.001);
    CHECK_INT(b.entries[0].is_new, 0);

    /* A counter that decreased must clamp to zero, not wrap around */
    CHECK_NEAR(b.entries[1].cpu_usr, 0.0, 0.001);
    CHECK_NEAR(b.entries[1].io_read_rate, 0.0, 0.001);
    CHECK_NEAR(b.entries[1].io_write_rate, 4000.0, 0.001);

    /* Unknown PID: lifetime totals must not be shown as this interval's load */
    CHECK_INT(b.entries[2].is_new, 1);
    CHECK_NEAR(b.entries[2].cpu_total, 0.0, 0.001);
    CHECK_NEAR(b.entries[2].io_read_rate, 0.0, 0.001);

    snapshot_free(&a);
    snapshot_free(&b);
}

static void test_deltas_any_order(void)
{
    /* Entries are matched by PID wherever they sit: B lists the processes
     * in another order than A, with strangers in between */
    enum { N = 300 };
    snapshot_t a, b;
    double tck = (double)sysconf(_SC_CLK_TCK);
    snapshot_init(&a);
    snapshot_init(&b);

    for (int i = 0; i < N; i++)
        fill(&a.entries[i], 1000 + i, 10UL * (unsigned long)i, 0, 0, 0);
    a.count = N;

    int n = 0;
    for (int i = N - 1; i >= 0; i--) {              /* reversed */
        fill(&b.entries[n++], 1000 + i, 10UL * (unsigned long)i + (unsigned long)(i % 7), 0, 0, 0);
        if (i % 50 == 0)
            fill(&b.entries[n++], 5000 + i, 777, 0, 0, 0);   /* unknown PID */
    }
    b.count = n;

    compute_deltas(&a, &b, 1.0);

    int wrong = 0, fresh = 0;
    for (int i = 0; i < b.count; i++) {
        proc_info_t *e = &b.entries[i];
        if (e->pid >= 5000) {
            fresh += e->is_new;
            if (e->cpu_total != 0.0) wrong++;
        } else {
            double want = (double)((e->pid - 1000) % 7) * 100.0 / tck;
            if (e->is_new || e->cpu_usr < want - 0.001 || e->cpu_usr > want + 0.001) wrong++;
        }
    }
    CHECK_INT(wrong, 0);
    CHECK_INT(fresh, 6);

    snapshot_free(&a);
    snapshot_free(&b);
}

static void test_pid_reuse(void)
{
    /* Same PID, different start time: another process got the recycled PID.
     * Its counters must not be diffed against the dead one's. */
    snapshot_t a, b;
    snapshot_init(&a);
    snapshot_init(&b);
    scan_one(&a, make_proc("r1", stat_rec(FAKE_PID, "old", USER_FLAGS, 500, 500, 1000),
                           status_rec(FAKE_PID, FAKE_PID, 64, 1), IO_REC), 0);
    scan_one(&b, make_proc("r1", stat_rec(FAKE_PID, "new", USER_FLAGS, 600, 500, 99999),
                           status_rec(FAKE_PID, FAKE_PID, 64, 1), IO_REC), 0);
    CHECK_INT(a.count, 1);
    CHECK_INT(b.count, 1);
    if (a.count == 1 && b.count == 1) {
        compute_deltas(&a, &b, 1.0);
        CHECK_INT(b.entries[0].is_new, 1);
        CHECK_NEAR(b.entries[0].cpu_total, 0.0, 0.001);
    }
    snapshot_free(&a);
    snapshot_free(&b);
}

static void test_sort_order(void)
{
    /* CPU descending, then RSS descending, then PID ascending */
    proc_info_t v[6];
    memset(v, 0, sizeof(v));
    v[0].pid = 50; v[0].cpu_total =  0.0; v[0].rss_kb = 100;
    v[1].pid = 40; v[1].cpu_total = 12.5; v[1].rss_kb =  10;
    v[2].pid = 30; v[2].cpu_total =  0.0; v[2].rss_kb = 900;
    v[3].pid = 20; v[3].cpu_total = 99.0; v[3].rss_kb =   1;
    v[4].pid = 10; v[4].cpu_total =  0.0; v[4].rss_kb = 100;
    v[5].pid = 60; v[5].cpu_total = 12.5; v[5].rss_kb =  20;
    qsort(v, 6, sizeof(v[0]), cmp_cpu_desc);
    CHECK_INT(v[0].pid, 20);
    CHECK_INT(v[1].pid, 60);
    CHECK_INT(v[2].pid, 40);
    CHECK_INT(v[3].pid, 30);
    CHECK_INT(v[4].pid, 10);
    CHECK_INT(v[5].pid, 50);
}

static void test_fmt_mem(void)
{
    char s[32];
    fmt_mem(0, s, sizeof(s));               CHECK_STR(s, "0K");
    fmt_mem(1023, s, sizeof(s));            CHECK_STR(s, "1023K");
    fmt_mem(1024, s, sizeof(s));            CHECK_STR(s, "1.0M");
    fmt_mem(1536, s, sizeof(s));            CHECK_STR(s, "1.5M");
    fmt_mem(1024 * 1024, s, sizeof(s));     CHECK_STR(s, "1.00G");
    fmt_mem(5L * 1024 * 1024 / 2, s, sizeof(s)); CHECK_STR(s, "2.50G");
}

static void test_fmt_bytes_rate(void)
{
    char s[32];
    fmt_bytes_rate(0.0, s, sizeof(s));                  CHECK_STR(s, "     0 B/s");
    fmt_bytes_rate(1023.0, s, sizeof(s));               CHECK_STR(s, "  1023 B/s");
    fmt_bytes_rate(1024.0, s, sizeof(s));               CHECK_STR(s, "   1.0 KB/s");
    fmt_bytes_rate(1536.0 * 1024.0, s, sizeof(s));      CHECK_STR(s, "   1.5 MB/s");
    fmt_bytes_rate(3.0 * 1024 * 1024 * 1024, s, sizeof(s)); CHECK_STR(s, "  3.00 GB/s");
}

static void test_sleep_duration(void)
{
    double t0 = monotonic_sec();
    precise_sleep(0.05);
    double dt = monotonic_sec() - t0;
    CHECK(dt >= 0.049);
    CHECK(dt < 0.5);
}

static void test_sleep_honours_stop_flag(void)
{
    /* SIGINT/SIGTERM handled while /proc was being scanned: the flag is
     * already down when the sleep starts, so it must not sleep at all */
    g_running = 0;
    double t0 = monotonic_sec();
    precise_sleep(0.4);
    double dt = monotonic_sec() - t0;
    g_running = 1;
    CHECK(dt < 0.2);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: unit_libc <scratch dir>\n");
        return 2;
    }
    snprintf(g_dir, sizeof(g_dir), "%s", argv[1]);
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("== unit tests: getpid.c ==\n");
    RUN(test_read_file,                 "read_file: missing file, content, truncation");
    RUN(test_stat_basic,                "stat: pid, comm, utime, stime");
    RUN(test_stat_tricky_comm,          "stat: comm with spaces/parentheses, long comm");
    RUN(test_stat_unreadable_or_garbage,"stat: missing or malformed file is rejected");
    RUN(test_stat_truncated,            "[B14] stat: truncated record is rejected, no stale fields");
    RUN(test_scan_one_fields,           "scan_one: stat + status + io merged into one entry");
    RUN(test_scan_one_missing_files,    "scan_one: missing io/status tolerated, missing stat skipped");
    RUN(test_scan_one_thread_tgid,      "scan_one: thread entry keeps TID and owning TGID");
    RUN(test_status_long_groups,        "[B7] status: RSS survives a file larger than 4 KiB");
    RUN(test_kernel_thread_flag,        "[B1] kernel thread verdict comes from stat flags");
    RUN(test_snapshot_growth,           "snapshot: grows past the initial capacity intact");
    RUN(test_deltas,                    "deltas: CPU%, I/O rate, clamping, new process");
    RUN(test_deltas_any_order,          "deltas: entries matched by PID in any order");
    RUN(test_pid_reuse,                 "[B13] deltas: recycled PID is treated as a new process");
    RUN(test_sort_order,                "sort: CPU desc, RSS desc, PID asc");
    RUN(test_fmt_mem,                   "format: memory sizes");
    RUN(test_fmt_bytes_rate,            "format: I/O rates");
    RUN(test_sleep_duration,            "sleep: lasts as long as requested");
    RUN(test_sleep_honours_stop_flag,   "[B11] sleep: returns at once if a stop was already requested");

    printf("-- getpid.c: %d tests, %d failed\n\n", t_tests, t_failed);
    return t_failed ? 1 : 0;
}
