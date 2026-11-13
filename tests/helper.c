/*
 * helper.c — workload / fixture process generator for the getpid test suite.
 *
 * Every mode prints one line "ready <pid> [extra]" on stdout once the fixture
 * is in place, then stays alive for SECS seconds (or until killed).
 *
 *   helper sleep      SECS [ARGS...]      idle process (extra args only shape cmdline)
 *   helper burn-user  SECS                busy loop in user mode
 *   helper burn-sys   SECS                busy loop inside the kernel (syscalls)
 *   helper threads    SECS N              N extra sleeping threads, one of them burning CPU
 *   helper proctitle  SECS TITLE [PAD...] setproctitle()-style argv rewrite, NUL padded
 *   helper blank      SECS [PAD...]       argv area wiped to all NULs
 *   helper comm       SECS NAME           prctl(PR_SET_NAME, NAME) (C escapes \e \n \t allowed)
 *   helper zombie     SECS [NAME]         leaves a zombie child (comm NAME); extra = zombie pid
 *   helper write      SECS FILE BYTES     appends BYTES to FILE once per 100 ms
 *   helper spawn-late SECS DELAY_MS ARGS  forks a child after DELAY_MS that execs "helper sleep SECS ARGS"
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void ready(long extra)
{
    if (extra >= 0) printf("ready %d %ld\n", (int)getpid(), extra);
    else            printf("ready %d\n", (int)getpid());
    fflush(stdout);
}

static void idle(double secs)
{
    double end = now() + secs;
    while (now() < end) usleep(50 * 1000);
}

static void burn_user(double secs)
{
    double end = now() + secs;
    volatile unsigned long x = 0;
    while (now() < end)
        for (int i = 0; i < 2000000; i++) x += (unsigned long)i * 31u;
}

static void burn_sys(double secs)
{
    double end = now() + secs;
    int fd = open("/dev/zero", O_RDONLY);
    static char buf[1 << 16];
    while (now() < end)
        for (int i = 0; i < 2000; i++)
            if (read(fd, buf, sizeof(buf)) < 0) _exit(3);
}

static void *thr_sleep(void *arg) { idle(*(double *)arg); return NULL; }
static void *thr_burn(void *arg)
{
    prctl(PR_SET_NAME, "burner-thread");
    printf("tid %ld\n", (long)syscall(SYS_gettid));
    fflush(stdout);
    burn_user(*(double *)arg);
    return NULL;
}

/* Decode \e \n \t \r \\ so tests can pass control characters on argv. */
static void unescape(char *s)
{
    char *w = s;
    for (; *s; s++) {
        if (*s == '\\' && s[1]) {
            s++;
            *w++ = (*s == 'e') ? 27 : (*s == 'n') ? '\n' : (*s == 't') ? '\t'
                 : (*s == 'r') ? '\r' : *s;
        } else {
            *w++ = *s;
        }
    }
    *w = '\0';
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: helper MODE SECS [ARGS...]\n");
        return 2;
    }
    const char *mode = argv[1];
    static double secs;
    secs = atof(argv[2]);

    /* The whole argv area as the kernel exposes it via /proc/PID/cmdline. */
    char  *area     = argv[0];
    size_t area_len = (size_t)(argv[argc - 1] + strlen(argv[argc - 1]) + 1 - argv[0]);

    if (!strcmp(mode, "sleep")) {
        ready(-1);
        idle(secs);
    } else if (!strcmp(mode, "burn-user")) {
        ready(-1);
        burn_user(secs);
    } else if (!strcmp(mode, "burn-sys")) {
        ready(-1);
        burn_sys(secs);
    } else if (!strcmp(mode, "threads") && argc >= 4) {
        int n = atoi(argv[3]);
        pthread_t t;
        for (int i = 0; i < n; i++)
            if (pthread_create(&t, NULL, i == 0 ? thr_burn : thr_sleep, &secs)) return 3;
        usleep(100 * 1000);
        ready(n + 1);
        idle(secs);
    } else if (!strcmp(mode, "proctitle") && argc >= 4) {
        char title[256];
        snprintf(title, sizeof(title), "%s", argv[3]);
        memset(area, 0, area_len);
        strncpy(area, title, area_len - 1);
        ready((long)area_len);
        idle(secs);
    } else if (!strcmp(mode, "blank")) {
        memset(area, 0, area_len);
        ready((long)area_len);
        idle(secs);
    } else if (!strcmp(mode, "comm") && argc >= 4) {
        unescape(argv[3]);
        prctl(PR_SET_NAME, argv[3]);
        ready(-1);
        idle(secs);
    } else if (!strcmp(mode, "zombie")) {
        if (argc >= 4) {            /* the zombie inherits this comm */
            unescape(argv[3]);
            prctl(PR_SET_NAME, argv[3]);
        }
        pid_t c = fork();
        if (c == 0) _exit(0);
        usleep(100 * 1000);         /* child is now a zombie: never reaped */
        ready((long)c);
        idle(secs);
    } else if (!strcmp(mode, "write") && argc >= 5) {
        long bytes = atol(argv[4]);
        int fd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { perror("open"); return 3; }
        char *buf = calloc(1, (size_t)bytes);
        ready(-1);
        double end = now() + secs;
        /* Append: write_bytes only counts pages that turn from clean to
         * dirty, so rewriting the same range would be accounted once. */
        while (now() < end) {
            if (write(fd, buf, (size_t)bytes) < 0) { perror("write"); return 3; }
            usleep(100 * 1000);
        }
        close(fd);
        unlink(argv[3]);
    } else if (!strcmp(mode, "spawn-late") && argc >= 5) {
        int delay_ms = atoi(argv[3]);
        ready(-1);
        usleep((useconds_t)delay_ms * 1000);
        pid_t c = fork();
        if (c == 0) {
            char *nargv[64];
            int k = 0;
            nargv[k++] = argv[0];
            nargv[k++] = "sleep";
            nargv[k++] = argv[2];
            for (int i = 4; i < argc && k < 63; i++) nargv[k++] = argv[i];
            nargv[k] = NULL;
            execv("/proc/self/exe", nargv);
            _exit(3);
        }
        printf("child %d\n", (int)c);
        fflush(stdout);
        idle(secs);
        kill(c, SIGKILL);
        waitpid(c, NULL, 0);
    } else {
        fprintf(stderr, "helper: bad mode/args\n");
        return 2;
    }
    return 0;
}
