/*
 * unit_raw.c — unit tests for the internals of getpid_raw.c.
 *
 * Freestanding like the program itself: no libc, same compiler flags.  The
 * test #includes getpid_raw.c (with its _start renamed) and drives the static
 * functions directly, reusing the program's own syscall wrappers.  The /proc
 * parsers take a path, so they are fed fixture files instead of the live
 * /proc.
 *
 * Usage: unit_raw <empty scratch directory>
 *
 * Titles that start with a tag like [B7] are regression tests.  The commit
 * that fixed the bug carries the same tag: git log --grep='\[B7\]'.
 */
#define _start getpid_raw_entry
#include GETPID_RAW_SRC         /* "/abs/path/getpid_raw.c", set by the Makefile */
#undef _start

/* ───────────────────────────── mini framework ───────────────────────────── */

static int t_tests, t_failed, t_bad;

static void t_puts(const char *s) { sys_write(1, s, str_len(s)); }

static void t_putnum(long v)
{
    char b[24];
    int pos = 23;
    unsigned long u = (v < 0) ? 0UL - (unsigned long)v : (unsigned long)v;
    b[pos] = '\0';
    do { b[--pos] = (char)('0' + u % 10); u /= 10; } while (u);
    if (v < 0) b[--pos] = '-';
    t_puts(b + pos);
}

static void t_where(int line, const char *expr)
{
    t_bad++;
    t_puts("        line "); t_putnum(line); t_puts(": "); t_puts(expr);
}

static void t_fail_expr(int line, const char *expr)
{
    t_bad++;
    t_puts("        line "); t_putnum(line); t_puts(": expected: "); t_puts(expr); t_puts("\n");
}

static void t_fail_int(int line, const char *expr, long got, long want)
{
    t_where(line, expr);
    t_puts(" = "); t_putnum(got); t_puts(", want "); t_putnum(want); t_puts("\n");
}

static void t_fail_str(int line, const char *expr, const char *got, const char *want)
{
    t_where(line, expr);
    t_puts(" = \""); t_puts(got); t_puts("\", want \""); t_puts(want); t_puts("\"\n");
}

#define CHECK(cond) \
    do { if (!(cond)) t_fail_expr(__LINE__, #cond); } while (0)
#define CHECK_INT(got, want) \
    do { long g_ = (long)(got), w_ = (long)(want); \
         if (g_ != w_) t_fail_int(__LINE__, #got, g_, w_); } while (0)
#define CHECK_STR(got, want) \
    do { const char *g_ = (got), *w_ = (want); \
         if (str_cmp(g_, w_) != 0) t_fail_str(__LINE__, #got, g_, w_); } while (0)

#define RUN(fn, title) \
    do { t_tests++; t_bad = 0; fn(); \
         if (t_bad) t_failed++; \
         t_puts(t_bad ? "FAIL  " : "ok    "); t_puts(title); t_puts("\n"); } while (0)

/* Whatever the out_* helpers queued for stdout since the last call. */
static const char *cap(void)
{
    static char copy[OUTBUF_SIZE + 1];
    mem_copy(copy, g_outbuf, (size_t)g_outpos);
    copy[g_outpos] = '\0';
    g_outpos = 0;
    return copy;
}

/* ──────────────────────────────── fixtures ──────────────────────────────── */

#define T_SYS_mkdir   83
#define T_SYS_unlink  87
#define T_O_WRONLY    01
#define T_O_CREAT     0100
#define T_O_TRUNC     01000

static char g_dir[512];

/* Tiny string builder standing in for snprintf */
static char sb_buf[32 * 1024];
static int  sb_len;

static void sb_reset(void) { sb_len = 0; sb_buf[0] = '\0'; }

static void sb_str(const char *s)
{
    while (*s && sb_len < (int)sizeof(sb_buf) - 1) sb_buf[sb_len++] = *s++;
    sb_buf[sb_len] = '\0';
}

static void sb_num(unsigned long v)
{
    char b[24];
    int pos = 23;
    b[pos] = '\0';
    do { b[--pos] = (char)('0' + v % 10); v /= 10; } while (v);
    sb_str(b + pos);
}

static void sb_copy_to(char *dst, int dstsz)
{
    int n = (sb_len < dstsz - 1) ? sb_len : dstsz - 1;
    mem_copy(dst, sb_buf, (size_t)n);
    dst[n] = '\0';
}

/* Path inside the scratch dir.  Rotating buffers: a few may be alive at once. */
static const char *fx(const char *name)
{
    static char bufs[4][700];
    static int  next;
    char *b = bufs[next++ % 4];
    sb_reset(); sb_str(g_dir); sb_str("/"); sb_str(name);
    sb_copy_to(b, 700);
    return b;
}

static void put_file(const char *path, const char *data)
{
    int fd = (int)syscall3(SYS_open, (long)path, T_O_WRONLY | T_O_CREAT | T_O_TRUNC, 0600);
    size_t len = str_len(data), off = 0;
    if (fd < 0) { t_puts("cannot create "); t_puts(path); t_puts("\n"); sys_exit(2); }
    while (off < len) {
        ssize_t n = sys_write(fd, data + off, len - off);
        if (n <= 0) { t_puts("cannot write "); t_puts(path); t_puts("\n"); sys_exit(2); }
        off += (size_t)n;
    }
    sys_close(fd);
}

/* One /proc/PID/stat record.  Fields after ")": state(0) ppid(1) pgrp(2)
 * session(3) tty(4) tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9)
 * cmajflt(10) utime(11) stime(12) ... num_threads(17) ... starttime(19) */
static const char *stat_rec(int pid, const char *comm, unsigned long flags,
                            unsigned long utime, unsigned long stime,
                            unsigned long starttime)
{
    static char rec[1024];
    sb_reset();
    sb_num((unsigned long)pid); sb_str(" ("); sb_str(comm); sb_str(") S 1 ");
    sb_num((unsigned long)pid); sb_str(" "); sb_num((unsigned long)pid);
    sb_str(" 0 -1 "); sb_num(flags); sb_str(" 500 0 3 0 ");
    sb_num(utime); sb_str(" "); sb_num(stime);
    sb_str(" 0 0 20 0 3 0 "); sb_num(starttime);
    sb_str(" 10485760 300 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
    sb_copy_to(rec, (int)sizeof(rec));
    return rec;
}

/* A /proc/PID/status file with `ngroups` supplementary groups. */
static const char *status_rec(int tgid, int pid, long rss_kb, int ngroups)
{
    static char rec[32 * 1024];
    sb_reset();
    sb_str("Name:\tfixture\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t"); sb_num((unsigned long)tgid);
    sb_str("\nNgid:\t0\nPid:\t"); sb_num((unsigned long)pid);
    sb_str("\nPPid:\t1\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n"
           "Gid:\t1000\t1000\t1000\t1000\nFDSize:\t64\nGroups:\t");
    for (int i = 0; i < ngroups; i++) { sb_num(4000000000UL + (unsigned long)i); sb_str(" "); }
    sb_str("\nNStgid:\t"); sb_num((unsigned long)tgid);
    sb_str("\nNSpid:\t"); sb_num((unsigned long)pid);
    sb_str("\nVmPeak:\t   20480 kB\nVmSize:\t   10240 kB\nVmLck:\t       0 kB\n"
           "VmPin:\t       0 kB\nVmHWM:\t    "); sb_num((unsigned long)rss_kb);
    sb_str(" kB\nVmRSS:\t    "); sb_num((unsigned long)rss_kb);
    sb_str(" kB\nRssAnon:\t     100 kB\nRssFile:\t     200 kB\nRssShmem:\t       0 kB\n"
           "VmData:\t     300 kB\nVmStk:\t     132 kB\nVmExe:\t      20 kB\n"
           "VmLib:\t    1500 kB\nVmPTE:\t      40 kB\nVmSwap:\t       0 kB\n"
           "Threads:\t3\nSigQ:\t0/3600\nSigPnd:\t0000000000000000\n"
           "voluntary_ctxt_switches:\t10\nnonvoluntary_ctxt_switches:\t2\n");
    sb_copy_to(rec, (int)sizeof(rec));
    return rec;
}

static const char IO_REC[] =
    "rchar: 111111\nwchar: 222222\nsyscr: 33\nsyscw: 44\n"
    "read_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 999\n";

/* Fake /proc/<pid> directory; a NULL argument leaves that file out. */
static const char *make_proc(const char *name, const char *stat_txt,
                             const char *status_txt, const char *io_txt)
{
    static char dir[700], path[800];
    sb_reset(); sb_str(g_dir); sb_str("/"); sb_str(name);
    sb_copy_to(dir, (int)sizeof(dir));
    syscall2(T_SYS_mkdir, (long)dir, 0700);

    sb_reset(); sb_str(dir); sb_str("/stat"); sb_copy_to(path, (int)sizeof(path));
    if (stat_txt) put_file(path, stat_txt); else syscall1(T_SYS_unlink, (long)path);
    sb_reset(); sb_str(dir); sb_str("/status"); sb_copy_to(path, (int)sizeof(path));
    if (status_txt) put_file(path, status_txt); else syscall1(T_SYS_unlink, (long)path);
    sb_reset(); sb_str(dir); sb_str("/io"); sb_copy_to(path, (int)sizeof(path));
    if (io_txt) put_file(path, io_txt); else syscall1(T_SYS_unlink, (long)path);
    return dir;
}

#define USER_FLAGS    0x00400000UL                    /* PF_RANDOMIZE: ordinary process */
#define KTHREAD_FLAGS (0x00200000UL | 0x00008040UL)   /* PF_KTHREAD | ... */

/* A PID that cannot exist on the live system (above any pid_max). */
#define FAKE_PID 2000000001

#define T_INT_MIN  (-2147483647 - 1)
#define T_LONG_MIN (-9223372036854775807L - 1)

/* ───────────────────────────────── tests ────────────────────────────────── */

static void test_strings(void)
{
    const char *s = "a(b)c(d)";

    CHECK_INT(str_len(""), 0);
    CHECK_INT(str_len("abc"), 3);

    CHECK(str_cmp("abc", "abc") == 0);
    CHECK(str_cmp("abc", "abd") < 0);
    CHECK(str_cmp("b", "a") > 0);
    CHECK(str_cmp("ab", "abc") < 0);
    CHECK(str_cmp("-I", "-i") != 0);

    CHECK(str_ncmp("VmRSS:\t 12 kB", "VmRSS:", 6) == 0);
    CHECK(str_ncmp("VmRSX:", "VmRSS:", 6) != 0);
    CHECK(str_ncmp("Vm", "VmRSS:", 6) != 0);
    CHECK(str_ncmp("cancelled_write_bytes: 9", "write_bytes:", 12) != 0);

    CHECK(str_chr(s, '(') == s + 1);
    CHECK(str_rchr(s, ')') == s + 7);
    CHECK(str_chr(s, 'z') == NULL);
    CHECK(str_rchr(s, 'z') == NULL);

    CHECK(is_digit('0') && is_digit('9'));
    CHECK(!is_digit('/') && !is_digit(':') && !is_digit('a'));
}

static void test_number_parsing(void)
{
    CHECK_INT(str_to_int("0"), 0);
    CHECK_INT(str_to_int("  42abc"), 42);
    CHECK_INT(str_to_int("-17"), -17);
    CHECK_INT(str_to_int("+8"), 8);
    CHECK_INT(str_to_int("x"), 0);

    CHECK(str_to_ulong("18446744073709551615") == 18446744073709551615UL);
    CHECK(str_to_ulong("\t   123 kB") == 123);
    CHECK(str_to_ulong("") == 0);
}

static void test_out_numbers(void)
{
    out_ulong(0);                           CHECK_STR(cap(), "0");
    out_ulong(18446744073709551615UL);      CHECK_STR(cap(), "18446744073709551615");
    out_int(2147483647);                    CHECK_STR(cap(), "2147483647");
    out_int(T_INT_MIN);                     CHECK_STR(cap(), "-2147483648");

    out_fixed1(0);                          CHECK_STR(cap(), "0.0");
    out_fixed1(5);                          CHECK_STR(cap(), "0.5");
    out_fixed1(125);                        CHECK_STR(cap(), "12.5");
    out_fixed1(-125);                       CHECK_STR(cap(), "-12.5");
    out_fixed1(T_LONG_MIN);                 CHECK_STR(cap(), "-922337203685477580.8");

    out_int_rjust(42, 7);                   CHECK_STR(cap(), "     42");
    out_int_rjust(-42, 7);                  CHECK_STR(cap(), "    -42");
    out_int_rjust(12345678, 3);             CHECK_STR(cap(), "12345678");
    out_int_rjust(T_INT_MIN, 12);           CHECK_STR(cap(), " -2147483648");

    out_fixed1_rjust(0, 6);                 CHECK_STR(cap(), "   0.0");
    out_fixed1_rjust(1000, 6);              CHECK_STR(cap(), " 100.0");
    out_fixed1_rjust(-5, 6);                CHECK_STR(cap(), "  -0.5");
    out_fixed1_rjust(1234567, 6);           CHECK_STR(cap(), "123456.7");
    out_fixed1_rjust(T_LONG_MIN, 1);        CHECK_STR(cap(), "-922337203685477580.8");

    out_str_pad("ab", 5);                   CHECK_STR(cap(), "ab   ");
    out_str_pad("abcdef", 3);               CHECK_STR(cap(), "abcdef");
}

static void test_out_mem(void)
{
    out_mem_rjust(0, 8);                    CHECK_STR(cap(), "      0K");
    out_mem_rjust(1023, 8);                 CHECK_STR(cap(), "   1023K");
    out_mem_rjust(1024, 8);                 CHECK_STR(cap(), "    1.0M");
    out_mem_rjust(1536, 1);                 CHECK_STR(cap(), "1.5M");
    out_mem_rjust(1024 * 1024, 8);          CHECK_STR(cap(), "   1.00G");
    out_mem_rjust(5L * 1024 * 1024 / 2, 1); CHECK_STR(cap(), "2.50G");
}

static void test_out_io_rate(void)
{
    out_io_rate_rjust(0, 12);               CHECK_STR(cap(), "       0 B/s");
    out_io_rate_rjust(1023, 12);            CHECK_STR(cap(), "    1023 B/s");
    out_io_rate_rjust(1024, 12);            CHECK_STR(cap(), "    1.0 KB/s");
    out_io_rate_rjust(1536L * 1024, 12);    CHECK_STR(cap(), "    1.5 MB/s");
}

static void test_out_buffer_flush(void)
{
    /* Filling the buffer must flush, not overflow: route fd 1 to /dev/null
     * is not possible here, so only fill up to the brim and check the edge */
    g_outpos = 0;
    for (int i = 0; i < OUTBUF_SIZE; i++) out_char('x');
    CHECK_INT(g_outpos, OUTBUF_SIZE);
    CHECK(g_outbuf[0] == 'x' && g_outbuf[OUTBUF_SIZE - 1] == 'x');
    g_outpos = 0;
}

static void test_path_join(void)
{
    char buf[32];
    char guard[24];

    path_join(buf, (int)sizeof(buf), "/proc", "123");
    CHECK_STR(buf, "/proc/123");

    /* Too long for the destination: cut, terminated, nothing written past it */
    mem_set(guard, 'Z', sizeof(guard));
    path_join(guard, 16, "/a/very/long/base/path", "suffix");
    CHECK(str_len(guard) <= 15);
    int untouched = 1;
    for (int i = 16; i < (int)sizeof(guard); i++)
        if (guard[i] != 'Z') untouched = 0;
    CHECK(untouched);
}

static void test_parse_int_strict(void)
{
    static const struct { const char *s; int want; } good[] = {
        { "0", 0 }, { "42", 42 }, { "-7", -7 }, { "+7", 7 },
        { "2147483647", 2147483647 }, { "-2147483648", T_INT_MIN },
    };
    static const char *const bad[] = {
        "", "-", "+", "abc", "5x", " 5", "5 ", "1.5",
        "2147483648", "-2147483649", "99999999999",
    };

    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        int v = 12345;
        if (!parse_int_strict(good[i].s, &v) || v != good[i].want)
            t_fail_str(__LINE__, "parse_int_strict rejected or misread", good[i].s, "(accepted)");
    }
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int v = 12345;
        if (parse_int_strict(bad[i], &v))
            t_fail_str(__LINE__, "parse_int_strict accepted", bad[i], "(rejected)");
    }
}

static void test_parse_interval(void)
{
    static const struct { const char *s; int want_ms; } good[] = {
        { "1", 1000 }, { "0.5", 500 }, { ".5", 500 }, { "1.", 1000 },
        { "0.01", 10 }, { "0.0005", 0 }, { "1.2345", 1234 }, { "00012", 12000 },
        { "2147483.647", 2147483647 },
    };
    static const char *const bad[] = {
        "", ".", "abc", "-1", "+1", "1e3", "1.2.3", " 1", "1 ", "nan", "inf",
        "2147483.648", "99999999999",
    };

    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        int v = -1;
        if (!parse_interval_msec_strict(good[i].s, &v) || v != good[i].want_ms)
            t_fail_str(__LINE__, "parse_interval_msec_strict rejected or misread", good[i].s, "(accepted)");
    }
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int v = -1;
        if (parse_interval_msec_strict(bad[i], &v))
            t_fail_str(__LINE__, "parse_interval_msec_strict accepted", bad[i], "(rejected)");
    }
}

static void test_read_file(void)
{
    char buf[16];

    CHECK_INT(read_file(fx("does-not-exist"), buf, (int)sizeof(buf)), -1);

    put_file(fx("small"), "hello");
    CHECK_INT(read_file(fx("small"), buf, (int)sizeof(buf)), 5);
    CHECK_STR(buf, "hello");

    /* Longer than the buffer: cut at bufsz-1 and still NUL-terminated */
    put_file(fx("big"), "0123456789abcdefXYZ");
    CHECK_INT(read_file(fx("big"), buf, (int)sizeof(buf)), 15);
    CHECK_STR(buf, "0123456789abcde");
}

static void test_stat_basic(void)
{
    proc_info_t p;
    mem_set(&p, 0, sizeof(p));
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
    mem_set(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(77, "a) (b c) 9 9 9", USER_FLAGS, 31, 32, 1));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);
    CHECK_INT(p.pid, 77);
    CHECK_STR(p.comm, "a) (b c) 9 9 9");
    CHECK_INT(p.utime, 31);
    CHECK_INT(p.stime, 32);

    /* kworker names are longer than TASK_COMM_LEN */
    mem_set(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(78, "kworker/u16:3-events_unbound_long_description_xxxxxxxxxxxx",
                                  KTHREAD_FLAGS, 1, 2, 1));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);
    CHECK_STR(p.comm, "kworker/u16:3-events_unbound_long_description_xxxxxxxxxxxx");
}

static void test_stat_unreadable_or_garbage(void)
{
    proc_info_t p;
    mem_set(&p, 0, sizeof(p));
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
    mem_set(&p, 0, sizeof(p));
    put_file(fx("stat"), stat_rec(5, "full", USER_FLAGS, 4242, 4343, 1));
    CHECK_INT(parse_proc_stat(fx("stat"), &p), 0);

    /* Nothing after the comm: the parser must not walk past the terminator
     * (and pick up the stale utime/stime of the previous record) */
    mem_set(&p, 0, sizeof(p));
    put_file(fx("stat"), "7 (x)");
    CHECK_INT(parse_proc_stat(fx("stat"), &p), -1);
    CHECK_INT(p.utime, 0);
    CHECK_INT(p.stime, 0);

    /* Record that stops before utime/stime */
    mem_set(&p, 0, sizeof(p));
    put_file(fx("stat"), "7 (x) S 1 7 7 0 -1 4194304 500\n");
    CHECK_INT(parse_proc_stat(fx("stat"), &p), -1);
}

static void test_scan_one_fields(void)
{
    snapshot_t s;
    arena_reset();
    snap_init(&s);
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
}

static void test_scan_one_missing_files(void)
{
    snapshot_t s;
    arena_reset();
    snap_init(&s);

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
}

static void test_scan_one_thread_tgid(void)
{
    /* A thread: stat carries the TID, status the owning process */
    snapshot_t s;
    arena_reset();
    snap_init(&s);
    scan_one(&s, make_proc("t1", stat_rec(FAKE_PID + 5, "thr", USER_FLAGS, 9, 8, 7),
                           status_rec(FAKE_PID, FAKE_PID + 5, 256, 1), IO_REC), FAKE_PID);
    CHECK_INT(s.count, 1);
    if (s.count == 1) {
        CHECK_INT(s.entries[0].pid, FAKE_PID + 5);
        CHECK_INT(s.entries[0].tgid, FAKE_PID);
    }
}

static void test_status_long_groups(void)
{
    /* ~9 KiB "Groups:" line in front of VmRSS (user in 800 groups) */
    snapshot_t s;
    arena_reset();
    snap_init(&s);
    scan_one(&s, make_proc("p5", stat_rec(FAKE_PID, "many-groups", USER_FLAGS, 1, 2, 3),
                           status_rec(FAKE_PID, FAKE_PID, 5120, 800), IO_REC), 0);
    CHECK_INT(s.count, 1);
    if (s.count == 1) {
        CHECK_INT(s.entries[0].rss_kb, 5120);
        CHECK_INT(s.entries[0].tgid, FAKE_PID);
    }
}

static void test_kernel_thread_flag(void)
{
    /* The verdict must come from the task's own flags, not from whether we
     * happen to be allowed to resolve /proc/PID/exe */
    snapshot_t s;
    int saved = g_opts.hide_kernel;
    g_opts.hide_kernel = 1;
    arena_reset();
    snap_init(&s);
    scan_one(&s, make_proc("k1", stat_rec(FAKE_PID, "kworker/0:1", KTHREAD_FLAGS, 0, 5, 9),
                           NULL, NULL), 0);
    scan_one(&s, make_proc("u1", stat_rec(FAKE_PID + 1, "daemon", USER_FLAGS, 3, 5, 9),
                           status_rec(FAKE_PID + 1, FAKE_PID + 1, 900, 1), NULL), 0);
    g_opts.hide_kernel = saved;
    CHECK_INT(s.count, 2);
    if (s.count == 2) {
        CHECK_INT(s.entries[0].is_kernel, 1);
        CHECK_INT(s.entries[1].is_kernel, 0);
    }
}

static void test_arena(void)
{
    arena_reset();
    char *base = (char *)g_brk_cur;
    char *p1 = (char *)arena_alloc(1);
    char *p2 = (char *)arena_alloc(13);
    char *p3 = (char *)arena_alloc(8);

    CHECK(p1 == base);
    CHECK(((unsigned long)p1 & 7) == 0);
    CHECK_INT(p2 - p1, 8);          /* 1 byte rounded up to 8 */
    CHECK_INT(p3 - p2, 16);         /* 13 bytes rounded up to 16 */
    p3[7] = 'x';                    /* the memory is really there */
    CHECK(p3[7] == 'x');

    arena_reset();
    CHECK(g_brk_cur == g_brk_base);
    CHECK((void *)sys_brk(NULL) == g_brk_base);
}

static void test_snapshot_growth(void)
{
    /* More entries than SNAP_INIT_CAP: the array must grow, not drop */
    snapshot_t s;
    const char *dir = make_proc("g1", stat_rec(FAKE_PID, "grow", USER_FLAGS, 11, 22, 33),
                                status_rec(FAKE_PID, FAKE_PID, 128, 1), IO_REC);
    arena_reset();
    snap_init(&s);
    for (int i = 0; i < 2500; i++)
        scan_one(&s, dir, 0);
    CHECK_INT(s.count, 2500);
    CHECK(s.capacity >= 2500);

    int intact = 1;
    for (int i = 0; i < s.count; i++)
        if (s.entries[i].pid != FAKE_PID || s.entries[i].utime != 11 || s.entries[i].rss_kb != 128)
            intact = 0;
    CHECK(intact);
    arena_reset();
}

static void fill(proc_info_t *e, int pid, unsigned long ut, unsigned long st,
                 unsigned long rd, unsigned long wr)
{
    mem_set(e, 0, sizeof(*e));
    e->pid = pid;
    e->utime = ut;
    e->stime = st;
    e->io_read = rd;
    e->io_write = wr;
}

static void test_deltas(void)
{
    snapshot_t a, b;
    arena_reset();
    snap_init(&a);
    snap_init(&b);

    fill(&a.entries[0], 10, 100, 50, 1000, 5000);
    fill(&a.entries[1], 11, 900, 900, 7000, 7000);
    a.count = 2;

    fill(&b.entries[0], 10, 150, 60, 3048, 5000);   /* +50 usr, +10 sys, +2048 B read */
    fill(&b.entries[1], 11, 800, 900, 6000, 9000);  /* counters went backwards         */
    fill(&b.entries[2], 12, 99999, 99999, 1 << 20, 1 << 20);  /* not in snapshot A      */
    b.count = 3;

    compute_deltas(&a, &b, 500);        /* 500 ms, CLK_TCK = 100 */

    CHECK_INT(b.entries[0].cpu_usr_x10, 1000);      /* 50 ticks in 0.5 s = 100.0% */
    CHECK_INT(b.entries[0].cpu_sys_x10, 200);       /* 10 ticks in 0.5 s =  20.0% */
    CHECK_INT(b.entries[0].cpu_total_x10, 1200);
    CHECK_INT(b.entries[0].io_rd_rate, 4096);
    CHECK_INT(b.entries[0].io_wr_rate, 0);
    CHECK_INT(b.entries[0].is_new, 0);

    /* A counter that decreased must clamp to zero, not wrap around */
    CHECK_INT(b.entries[1].cpu_usr_x10, 0);
    CHECK_INT(b.entries[1].io_rd_rate, 0);
    CHECK_INT(b.entries[1].io_wr_rate, 4000);

    /* Unknown PID: lifetime totals must not be shown as this interval's load */
    CHECK_INT(b.entries[2].is_new, 1);
    CHECK_INT(b.entries[2].cpu_total_x10, 0);
    CHECK_INT(b.entries[2].io_rd_rate, 0);
}

static void test_deltas_any_order(void)
{
    /* Entries are matched by PID wherever they sit: B lists the processes
     * in another order than A, with strangers in between */
    enum { N = 300 };
    snapshot_t a, b;
    arena_reset();
    snap_init(&a);
    snap_init(&b);

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

    compute_deltas(&a, &b, 1000);       /* 1 s: one tick is 1.0% */

    int wrong = 0, fresh = 0;
    for (int i = 0; i < b.count; i++) {
        proc_info_t *e = &b.entries[i];
        if (e->pid >= 5000) {
            fresh += e->is_new;
            if (e->cpu_total_x10 != 0) wrong++;
        } else {
            if (e->is_new || e->cpu_usr_x10 != 10L * ((e->pid - 1000) % 7)) wrong++;
        }
    }
    CHECK_INT(wrong, 0);
    CHECK_INT(fresh, 6);
}

static void test_pid_reuse(void)
{
    /* Same PID, different start time: another process got the recycled PID.
     * Its counters must not be diffed against the dead one's. */
    snapshot_t a, b;
    arena_reset();
    snap_init(&a);
    snap_init(&b);
    scan_one(&a, make_proc("r1", stat_rec(FAKE_PID, "old", USER_FLAGS, 500, 500, 1000),
                           status_rec(FAKE_PID, FAKE_PID, 64, 1), IO_REC), 0);
    scan_one(&b, make_proc("r1", stat_rec(FAKE_PID, "new", USER_FLAGS, 600, 500, 99999),
                           status_rec(FAKE_PID, FAKE_PID, 64, 1), IO_REC), 0);
    CHECK_INT(a.count, 1);
    CHECK_INT(b.count, 1);
    if (a.count == 1 && b.count == 1) {
        compute_deltas(&a, &b, 1000);
        CHECK_INT(b.entries[0].is_new, 1);
        CHECK_INT(b.entries[0].cpu_total_x10, 0);
    }
}

static void test_sort_order(void)
{
    /* CPU descending, then RSS descending, then PID ascending */
    proc_info_t v[6];
    mem_set(v, 0, sizeof(v));
    v[0].pid = 50; v[0].cpu_total_x10 =   0; v[0].rss_kb = 100;
    v[1].pid = 40; v[1].cpu_total_x10 = 125; v[1].rss_kb =  10;
    v[2].pid = 30; v[2].cpu_total_x10 =   0; v[2].rss_kb = 900;
    v[3].pid = 20; v[3].cpu_total_x10 = 990; v[3].rss_kb =   1;
    v[4].pid = 10; v[4].cpu_total_x10 =   0; v[4].rss_kb = 100;
    v[5].pid = 60; v[5].cpu_total_x10 = 125; v[5].rss_kb =  20;
    sort_procs(v, 6);
    CHECK_INT(v[0].pid, 20);
    CHECK_INT(v[1].pid, 60);
    CHECK_INT(v[2].pid, 40);
    CHECK_INT(v[3].pid, 30);
    CHECK_INT(v[4].pid, 10);
    CHECK_INT(v[5].pid, 50);

    /* Edge sizes */
    sort_procs(v, 0);
    sort_procs(v, 1);
    CHECK_INT(v[0].pid, 20);
}

static void test_sort_large(void)
{
    /* Pseudo-random input: output ordered, nothing lost or duplicated */
    enum { N = 3000 };
    unsigned long seed = 88172645463325252UL, sum_before = 0, sum_after = 0;
    arena_reset();
    proc_info_t *v = (proc_info_t *)arena_alloc(N * sizeof(proc_info_t));
    mem_set(v, 0, N * sizeof(proc_info_t));
    for (int i = 0; i < N; i++) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        v[i].pid = i + 1;
        v[i].cpu_total_x10 = (long)(seed % 7 == 0 ? seed % 1000 : 0);
        v[i].rss_kb = (long)((seed >> 20) % 50);
        sum_before += (unsigned long)v[i].pid * 2654435761UL;
    }
    sort_procs(v, N);

    int ordered = 1;
    for (int i = 0; i + 1 < N; i++)
        if (proc_cmp(&v[i], &v[i + 1]) <= 0) ordered = 0;   /* pids are unique: strict order */
    for (int i = 0; i < N; i++)
        sum_after += (unsigned long)v[i].pid * 2654435761UL;
    CHECK(ordered);
    CHECK(sum_before == sum_after);
    arena_reset();
}

static void test_sleep_duration(void)
{
    long t0 = monotonic_ms();
    precise_sleep_ms(50);
    long dt = monotonic_ms() - t0;
    CHECK(dt >= 49);
    CHECK(dt < 500);
}

static void test_sleep_honours_stop_flag(void)
{
    /* SIGINT/SIGTERM handled while /proc was being scanned: the flag is
     * already down when the sleep starts, so it must not sleep at all */
    g_running = 0;
    long t0 = monotonic_ms();
    precise_sleep_ms(400);
    long dt = monotonic_ms() - t0;
    g_running = 1;
    CHECK(dt < 200);
}

static void test_detect_cores(void)
{
    CHECK(detect_cores() >= 1);
}

/* ──────────────────────────────── entry ─────────────────────────────────── */

static void test_main(long *sp) __attribute__((noreturn, used));

static void test_main(long *sp)
{
    int    argc = (int)sp[0];
    char **argv = (char **)(sp + 1);

    if (argc != 2) {
        t_puts("usage: unit_raw <scratch dir>\n");
        sys_exit(2);
    }
    sb_reset(); sb_str(argv[1]); sb_copy_to(g_dir, (int)sizeof(g_dir));

    arena_init();

    t_puts("== unit tests: getpid_raw.c ==\n");
    RUN(test_strings,                   "strings: len, cmp, ncmp, chr, rchr, is_digit");
    RUN(test_number_parsing,            "numbers: str_to_int, str_to_ulong");
    RUN(test_out_numbers,               "output: integers and fixed-point, incl. INT_MIN/LONG_MIN");
    RUN(test_out_mem,                   "output: memory sizes");
    RUN(test_out_io_rate,               "output: I/O rates");
    RUN(test_out_buffer_flush,          "output: buffer fills to the brim without overflow");
    RUN(test_path_join,                 "path_join: joins, truncates inside the buffer");
    RUN(test_parse_int_strict,          "options: strict integer parsing");
    RUN(test_parse_interval,            "options: strict interval parsing");
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
    RUN(test_arena,                     "arena: aligned bump allocation, reset returns the memory");
    RUN(test_snapshot_growth,           "snapshot: grows past the initial capacity intact");
    RUN(test_deltas,                    "deltas: CPU%, I/O rate, clamping, new process");
    RUN(test_deltas_any_order,          "deltas: entries matched by PID in any order");
    RUN(test_pid_reuse,                 "[B13] deltas: recycled PID is treated as a new process");
    RUN(test_sort_order,                "sort: CPU desc, RSS desc, PID asc");
    RUN(test_sort_large,                "sort: 3000 pseudo-random entries ordered, none lost");
    RUN(test_sleep_duration,            "sleep: lasts as long as requested");
    RUN(test_sleep_honours_stop_flag,   "[B11] sleep: returns at once if a stop was already requested");
    RUN(test_detect_cores,              "cores: at least one CPU detected");

    t_puts("-- getpid_raw.c: "); t_putnum(t_tests); t_puts(" tests, ");
    t_putnum(t_failed); t_puts(" failed\n\n");

    sys_exit(t_failed ? 1 : 0);
    __builtin_unreachable();
}

__attribute__((naked, noreturn))
void _start(void)
{
    __asm__ volatile(
        "xor  %%rbp, %%rbp\n\t"
        "mov  %%rsp, %%rdi\n\t"
        "and  $-16, %%rsp\n\t"
        "call test_main\n\t"
        "ud2\n\t"
        ::: "memory"
    );
}
