#!/usr/bin/env python3
"""End-to-end tests: run both getpid binaries against the live /proc.

Fixture processes with known properties (busy loop, threads, zombie, rewritten
title, control bytes in the name, ...) come from build/helper; the tests then
check what the tool reports about them.

Every test runs twice: once for the libc build (getpid) and once for the
freestanding build (getpid_raw).  Tests named test_B<n>_... are regression
tests.  The commit that fixed the bug carries the tag [B<n>] in its message:
git log --grep='\[B3\]'.

    GETPID_BUILD=<dir with getpid, getpid_raw, helper>  python3 test_cli.py [-v]
"""
import contextlib
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.abspath(os.environ.get("GETPID_BUILD", os.path.join(HERE, "build")))
HELPER = os.path.join(BUILD, "helper")

PF_KTHREAD = 0x00200000
ESC = b"\x1b"

RATE = r"(\d+(?:\.\d+)?) (B/s|KB/s|MB/s|GB/s)"
ROW_NOIO = re.compile(r"^ *(\d+)  (.*?) +(\d+\.\d) +(\d+\.\d) +(\d+\.\d) +(\d+(?:\.\d+)?[KMG])$")
ROW_IO = re.compile(r"^ *(\d+)  (.*?) +(\d+\.\d) +(\d+\.\d) +(\d+\.\d) +(\d+(?:\.\d+)?[KMG])"
                    r" +" + RATE + r" +" + RATE + r"$")
SUMMARY = re.compile(r"^CPU cores: (\d+)  \|  (Processes|Threads): (\d+)  \|  Interval: ([\d.]+)s"
                     r"  \|  Total CPU: ([\d.]+)%  \|  Total RSS: (\S+)$")

UNIT = {"K": 1, "M": 1024, "G": 1024 * 1024}
RATE_UNIT = {"B/s": 1, "KB/s": 1024, "MB/s": 1024 ** 2, "GB/s": 1024 ** 3}


def mem_kb(text):
    return float(text[:-1]) * UNIT[text[-1]]


class Table:
    """One printed frame, parsed."""

    def __init__(self, text):
        lines = text.split("\n")
        self.summary = None
        self.header = None
        self.separator = None
        self.rows = []
        self.junk = []          # lines after the separator that are not table rows
        sep_seen = False
        for line in lines:
            if not sep_seen:
                m = SUMMARY.match(line)
                if m:
                    self.summary = {
                        "cores": int(m.group(1)), "label": m.group(2), "count": int(m.group(3)),
                        "interval": float(m.group(4)), "cpu": float(m.group(5)),
                        "rss_kb": mem_kb(m.group(6)),
                    }
                elif "COMMAND" in line:
                    self.header = line
                elif line and set(line) == {"-"}:
                    self.separator = line
                    sep_seen = True
                continue
            if not line:
                continue
            m = ROW_IO.match(line) or ROW_NOIO.match(line)
            if not m:
                self.junk.append(line)
                continue
            row = {
                "pid": int(m.group(1)), "cmd": m.group(2), "usr": float(m.group(3)),
                "sys": float(m.group(4)), "cpu": float(m.group(5)), "rss_kb": mem_kb(m.group(6)),
                "line": line,
            }
            if m.re is ROW_IO:
                row["rd"] = float(m.group(7)) * RATE_UNIT[m.group(8)]
                row["wr"] = float(m.group(9)) * RATE_UNIT[m.group(10)]
            self.rows.append(row)

    def by_pid(self, pid):
        return [r for r in self.rows if r["pid"] == pid]

    def pids(self):
        return [r["pid"] for r in self.rows]


class Fixture:
    """A helper process in a known state; killed on exit."""

    def __init__(self, *args, cwd=None, exe=HELPER):
        self.proc = subprocess.Popen([exe] + [str(a) for a in args], cwd=cwd,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.pid = self.proc.pid
        self.extra = None
        self.info = {}
        for raw in self.proc.stdout:            # until "ready <pid> [extra]"
            words = raw.decode().split()
            if words and words[0] == "ready":
                if len(words) > 2:
                    self.extra = int(words[2])
                break
            if len(words) == 2:
                self.info[words[0]] = int(words[1])
        else:
            raise RuntimeError("helper %r died before it was ready" % (args,))

    def read_info(self, key, timeout=5.0):
        """Wait for a later "key value" line (e.g. the pid of a late child)."""
        end = time.time() + timeout
        while key not in self.info and time.time() < end:
            ready, _, _ = select.select([self.proc.stdout], [], [], 0.1)
            if ready:
                words = self.proc.stdout.readline().decode().split()
                if len(words) == 2:
                    self.info[words[0]] = int(words[1])
        return self.info.get(key)

    def close(self):
        with contextlib.suppress(ProcessLookupError):
            self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def status_field(pid, key):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith(key + ":"):
                return int(line.split()[1])
    return None


def task_flags(path):
    with open(path) as f:
        data = f.read()
    return int(data[data.rindex(")") + 2:].split()[6])


def kernel_thread_pids():
    out = set()
    for name in os.listdir("/proc"):
        if name.isdigit():
            with contextlib.suppress(OSError, ValueError):
                if task_flags("/proc/%s/stat" % name) & PF_KTHREAD:
                    out.add(int(name))
    return out


class Common:
    """Tests shared by both binaries; subclasses set NAME."""

    NAME = None
    maxDiff = None

    @property
    def exe(self):
        return os.path.join(BUILD, self.NAME)

    def run_raw(self, *args, timeout=20):
        return subprocess.run([self.exe] + [str(a) for a in args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

    def table(self, *args, timeout=20):
        """Run once, expect success, return (Table, raw stdout bytes)."""
        res = self.run_raw(*args, timeout=timeout)
        self.assertEqual(res.returncode, 0, "exit status; stderr: %r" % res.stderr[-300:])
        t = Table(res.stdout.decode("utf-8", "replace"))
        self.assertIsNotNone(t.summary, "summary line missing:\n%s" % res.stdout[:400])
        self.assertIsNotNone(t.header, "header line missing")
        self.assertIsNotNone(t.separator, "separator line missing")
        return t, res.stdout

    def run_on_pty(self, *args, seconds=1.0):
        """Run with a terminal on stdout; stop it with SIGINT after `seconds`."""
        master, slave = pty.openpty()
        proc = subprocess.Popen([self.exe] + [str(a) for a in args], stdin=subprocess.DEVNULL,
                                stdout=slave, stderr=subprocess.DEVNULL)
        os.close(slave)
        chunks = []
        end = time.time() + seconds
        sent = False
        while True:
            if not sent and time.time() >= end:
                proc.send_signal(signal.SIGINT)
                sent = True
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:             # EIO: slave side closed
                    break
                if not data:
                    break
                chunks.append(data)
            elif proc.poll() is not None:
                break
            if time.time() > end + 10:
                proc.kill()
                break
        proc.wait()
        os.close(master)
        return b"".join(chunks), proc.returncode

    # ───────────────────────────── basics ──────────────────────────────────

    def test_help(self):
        res = self.run_raw("-h")
        self.assertEqual(res.returncode, 0)
        text = (res.stdout + res.stderr).decode()
        for needle in ("Usage:", "-n", "-i", "-t", "-p", "-k", "-I", "-c"):
            self.assertIn(needle, text)

    def test_default_layout(self):
        t, raw = self.table("-i", "0.2")
        self.assertEqual(t.summary["label"], "Processes")
        self.assertEqual(t.summary["interval"], 0.2)
        self.assertGreater(t.summary["count"], 20)
        for col in ("PID", "COMMAND", "USR%", "SYS%", "CPU%", "RSS", "IO_RD/s", "IO_WR/s"):
            self.assertIn(col, t.header)
        self.assertEqual(len(t.rows), 20, "default is the top 20")
        self.assertEqual(t.junk, [])
        for r in t.rows:
            self.assertIn("rd", r, "I/O columns expected: %r" % r["line"])
            self.assertAlmostEqual(r["usr"] + r["sys"], r["cpu"], delta=0.11)

    def test_top_n_limits_rows(self):
        for n in (1, 5):
            t, _ = self.table("-n", n, "-i", "0.1")
            self.assertEqual(len(t.rows), n)

    def test_no_io_hides_columns(self):
        t, _ = self.table("-I", "-n", "5", "-i", "0.1")
        self.assertNotIn("IO_RD/s", t.header)
        self.assertNotIn("IO_WR/s", t.header)
        self.assertEqual(len(t.rows), 5)
        for r in t.rows:
            self.assertNotIn("rd", r)

    def test_rows_sorted_by_cpu(self):
        with Fixture("burn-user", 5):
            t, _ = self.table("-n", "100000", "-I", "-i", "0.5")
        cpus = [r["cpu"] for r in t.rows]
        self.assertEqual(cpus, sorted(cpus, reverse=True))
        self.assertGreater(cpus[0], 0.0)

    def test_summary_counts_all_processes(self):
        t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        self.assertEqual(t.summary["count"], len(t.rows))
        live = sum(1 for d in os.listdir("/proc") if d.isdigit())
        self.assertLess(abs(t.summary["count"] - live), 15)

    def test_row_width_is_constant(self):
        for args, width in ((("-I",), 88), ((), 116)):
            t, _ = self.table("-n", "100000", "-i", "0.1", *args)
            self.assertEqual(len(t.header), width)
            bad = [r["line"] for r in t.rows if len(r["line"]) != width]
            self.assertEqual(bad, [])

    def test_long_options(self):
        t, _ = self.table("--top", "3", "--interval", "0.1", "--no-io", "--hide-kernel")
        self.assertEqual(len(t.rows), 3)
        self.assertNotIn("IO_RD/s", t.header)
        t, _ = self.table("--top=4", "--interval=0.1", "--threads")
        self.assertEqual(len(t.rows), 4)
        self.assertIn("TID", t.header)

    def test_attached_short_values(self):
        t, _ = self.table("-n3", "-i0.1")
        self.assertEqual(len(t.rows), 3)

    def test_interval_is_honoured(self):
        t0 = time.time()
        self.table("-n", "1", "-i", "0.4")
        dt = time.time() - t0
        self.assertGreaterEqual(dt, 0.4)
        self.assertLess(dt, 1.5)

    # ──────────────────────────── accounting ────────────────────────────────

    def test_cpu_user_burner(self):
        with Fixture("burn-user", 6) as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "1")
        rows = t.by_pid(fx.pid)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertGreater(r["cpu"], 25.0, r["line"])
        self.assertLess(r["cpu"], 100.0 * t.summary["cores"] + 15.0, r["line"])
        self.assertGreater(r["usr"], 5 * r["sys"], r["line"])
        self.assertEqual(t.rows[0]["pid"], fx.pid, "busiest process must be listed first")

    def test_cpu_system_burner(self):
        with Fixture("burn-sys", 6) as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "1")
        r = t.by_pid(fx.pid)[0]
        self.assertGreater(r["cpu"], 25.0, r["line"])
        self.assertGreater(r["sys"], 2 * r["usr"], r["line"])

    def test_idle_process_shows_no_cpu(self):
        with Fixture("sleep", 5) as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "0.5")
        r = t.by_pid(fx.pid)[0]
        self.assertLess(r["cpu"], 5.0, r["line"])

    def test_rss_matches_proc(self):
        with Fixture("sleep", 5) as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "0.2")
            want = status_field(fx.pid, "VmRSS")
        r = t.by_pid(fx.pid)[0]
        self.assertGreater(want, 100)
        self.assertAlmostEqual(r["rss_kb"], want, delta=max(120.0, want * 0.1), msg=r["line"])

    def test_disk_write_rate(self):
        path = os.path.join(BUILD, "io-%s.tmp" % self.NAME)
        with Fixture("write", 6, path, 65536) as fx:
            time.sleep(0.4)
            with open("/proc/%d/io" % fx.pid) as f:
                counters = dict(line.split(": ") for line in f.read().splitlines())
            if int(counters["write_bytes"]) == 0:
                self.skipTest("this filesystem does not account write_bytes")
            t, _ = self.table("-n", "100000", "-i", "1")
        with contextlib.suppress(OSError):
            os.unlink(path)
        r = t.by_pid(fx.pid)[0]
        # 64 KiB every 100 ms is about 640 KiB/s
        self.assertGreater(r["wr"], 100 * 1024, r["line"])
        self.assertLess(r["wr"], 4 * 1024 * 1024, r["line"])

    # ───────────────────────── threads and -p PID ──────────────────────────

    def test_thread_view_lists_every_tid(self):
        with Fixture("threads", 6, 3) as fx:
            tids = sorted(int(x) for x in os.listdir("/proc/%d/task" % fx.pid))
            t, _ = self.table("-t", "-n", "100000", "-I", "-i", "0.5")
        self.assertEqual(len(tids), 4)
        self.assertIn("TID", t.header)
        self.assertNotIn("PID", t.header)
        shown = sorted(p for p in t.pids() if p in tids)
        self.assertEqual(shown, tids)

    def test_focus_pid_shows_its_threads_only(self):
        with Fixture("threads", 6, 3) as fx:
            tids = sorted(int(x) for x in os.listdir("/proc/%d/task" % fx.pid))
            t, _ = self.table("-p", fx.pid, "-I", "-i", "1")
        self.assertIn("TID", t.header)
        self.assertEqual(sorted(t.pids()), tids)
        self.assertEqual(t.rows[0]["pid"], fx.info["tid"], "the burning thread comes first")
        self.assertGreater(t.rows[0]["cpu"], 25.0)
        for r in t.rows[1:]:
            self.assertLess(r["cpu"], 5.0, r["line"])

    def test_B2_thread_view_counts_rss_once_per_process(self):
        with Fixture("threads", 6, 3) as fx:
            t, _ = self.table("-p", fx.pid, "-I", "-i", "0.3")
            want = status_field(fx.pid, "VmRSS")
        self.assertEqual(len(t.rows), 4)
        # 4 threads share one address space: the total is the process RSS, not 4x
        self.assertAlmostEqual(t.summary["rss_kb"], want, delta=max(150.0, want * 0.15),
                               msg="Total RSS for a 4-thread process with VmRSS %d kB" % want)

    def test_B2_thread_view_total_rss_matches_process_view(self):
        p, _ = self.table("-n", "1", "-I", "-i", "0.2")
        t, _ = self.table("-t", "-n", "1", "-I", "-i", "0.2")
        self.assertGreater(t.summary["count"], p.summary["count"])
        ratio = t.summary["rss_kb"] / p.summary["rss_kb"]
        self.assertLess(abs(ratio - 1.0), 0.25,
                        "Total RSS: %.0f kB by process, %.0f kB by thread"
                        % (p.summary["rss_kb"], t.summary["rss_kb"]))

    def test_B6_focus_accepts_a_thread_id(self):
        with Fixture("threads", 6, 3) as fx:
            tid = fx.info["tid"]
            self.assertNotEqual(tid, fx.pid)
            tids = sorted(int(x) for x in os.listdir("/proc/%d/task" % fx.pid))
            res = self.run_raw("-p", tid, "-I", "-i", "0.3")
        t = Table(res.stdout.decode("utf-8", "replace"))
        self.assertEqual(sorted(t.pids()), tids,
                         "-p <tid of a secondary thread> should show its process")

    def test_B6_focus_on_missing_pid_is_an_error(self):
        res = self.run_raw("-p", "4000000", "-I", "-i", "0.2")
        self.assertNotEqual(res.returncode, 0, "exit status for a PID that does not exist")
        self.assertIn(b"4000000", res.stderr)
        self.assertNotIn(b"COMMAND", res.stdout, "no empty table expected")

    def test_B6_continuous_focus_ends_when_target_exits(self):
        with Fixture("sleep", "0.7") as fx:
            proc = subprocess.Popen([self.exe, "-c", "-p", str(fx.pid), "-I", "-i", "0.2"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            fx.proc.wait()          # reap it: the PID is really gone now
            try:
                out, err = proc.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                self.fail("still refreshing an empty table %d frames after the target exited"
                          % out.count(b"CPU cores"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(str(fx.pid).encode(), err)

    # ─────────────────────────── kernel threads ─────────────────────────────

    def test_kernel_threads_listed_by_default(self):
        t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        rows = t.by_pid(2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cmd"], "[kthreadd]")

    def test_k_hides_kernel_threads(self):
        before = kernel_thread_pids()
        t, _ = self.table("-k", "-n", "100000", "-I", "-i", "0.1")
        after = kernel_thread_pids()
        self.assertGreater(len(before), 5)
        self.assertEqual(sorted(set(t.pids()) & before & after), [])
        self.assertGreater(len(t.rows), 5)

    def test_k_does_not_use_up_the_row_quota(self):
        t, _ = self.table("-k", "-n", "7", "-I", "-i", "0.1")
        self.assertEqual(len(t.rows), 7)

    def test_B1_k_keeps_processes_of_other_users(self):
        if os.geteuid() == 0:
            self.skipTest("needs an unprivileged user")
        try:
            os.stat("/proc/1/exe")
            self.skipTest("/proc/1/exe is readable here")
        except PermissionError:
            pass
        self.assertFalse(task_flags("/proc/1/stat") & PF_KTHREAD)
        t, _ = self.table("-k", "-n", "100000", "-I", "-i", "0.1")
        self.assertEqual(len(t.by_pid(1)), 1, "PID 1 (init, not a kernel thread) must stay visible")
        hidden = []
        for name in os.listdir("/proc"):
            if name.isdigit() and int(name) not in t.pids():
                with contextlib.suppress(OSError, ValueError):
                    if not task_flags("/proc/%s/stat" % name) & PF_KTHREAD:
                        hidden.append(int(name))
        # allow for a few processes born after the snapshot
        self.assertLess(len(hidden), 4, "userspace processes hidden by -k: %s" % sorted(hidden)[:20])

    def test_B1_k_keeps_zombies(self):
        with Fixture("zombie", 5) as fx:
            zombie = fx.extra
            self.assertFalse(task_flags("/proc/%d/stat" % zombie) & PF_KTHREAD)
            t, _ = self.table("-k", "-n", "100000", "-I", "-i", "0.1")
        self.assertEqual(len(t.by_pid(zombie)), 1, "a zombie is not a kernel thread")

    # ───────────────────────── command rendering ────────────────────────────

    def test_arguments_joined_with_spaces(self):
        with Fixture("sleep", 5, "alpha", "beta gamma", cwd=BUILD, exe="./helper") as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        self.assertEqual(t.by_pid(fx.pid)[0]["cmd"], "./helper sleep 5 alpha beta gamma")

    def test_long_command_is_truncated(self):
        with Fixture("sleep", 5, "x" * 80, cwd=BUILD, exe="./helper") as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        cmd = t.by_pid(fx.pid)[0]["cmd"]
        self.assertEqual(len(cmd), 44)
        self.assertEqual(cmd, "./helper sleep 5 " + "x" * 24 + "...")

    def test_zombie_falls_back_to_comm(self):
        with Fixture("zombie", 5) as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        self.assertEqual(t.by_pid(fx.extra)[0]["cmd"], "[helper]")

    def test_B5_rewritten_title_has_no_padding(self):
        # setproctitle()-style: short title, rest of the argv area NUL-filled
        with Fixture("proctitle", 5, "postgres: checkpointer", "x" * 70) as fx:
            self.assertGreater(fx.extra, 80)
            t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        self.assertEqual(t.by_pid(fx.pid)[0]["cmd"], "postgres: checkpointer")

    def test_B5_wiped_argv_falls_back_to_comm(self):
        with Fixture("blank", 5, "x" * 70) as fx:
            t, _ = self.table("-n", "100000", "-I", "-i", "0.1")
        rows = t.by_pid(fx.pid)
        self.assertEqual(len(rows), 1, "row missing or unparsable: %r" % t.junk[:3])
        self.assertEqual(rows[0]["cmd"], "[helper]")

    def test_B3_control_bytes_in_cmdline_are_neutralised(self):
        args = ["\x1b[31mRED\x1b[2J", "x\n      1  /sbin/init FAKE-ROW", "tab\there", "\r"]
        with Fixture("sleep", 5, *args, cwd=BUILD, exe="./helper") as fx:
            t, raw = self.table("-n", "100000", "-I", "-i", "0.1")
        self.assertNotIn(ESC, raw, "escape byte reached the output")
        self.assertNotIn(b"\r", raw)
        self.assertNotIn(b"\t", raw)
        self.assertEqual(t.junk, [], "a newline in argv split the row")
        self.assertEqual(len(t.by_pid(fx.pid)), 1)
        self.assertEqual(len(t.by_pid(1)), 1, "forged row for PID 1")

    def test_B3_control_bytes_in_comm_are_neutralised(self):
        with Fixture("zombie", 5, r"ev\e[41mil\nX") as fx:
            t, raw = self.table("-n", "100000", "-I", "-i", "0.1")
        self.assertNotIn(ESC, raw, "escape byte reached the output")
        self.assertEqual(t.junk, [], "a newline in comm split the row")
        rows = t.by_pid(fx.extra)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["cmd"].startswith("[ev"), rows[0]["cmd"])

    def test_B3_non_ascii_bytes_do_not_break_the_table(self):
        with Fixture("sleep", 5, "café", "привет",
                     cwd=BUILD, exe="./helper") as fx:
            t, raw = self.table("-n", "100000", "-I", "-i", "0.1")
        rows = t.by_pid(fx.pid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["line"]), 88, "multi-byte characters shifted the columns")
        self.assertNotIn(b"\xc2\x9b", raw)

    def test_B9_new_tag_keeps_columns_aligned(self):
        for attempt in range(3):
            with Fixture("spawn-late", 4, 350, "y" * 70, cwd=BUILD, exe="./helper") as fx:
                t, _ = self.table("-n", "100000", "-I", "-i", "1")
                child = fx.read_info("child")
            rows = t.by_pid(child) if child else []
            if rows and "[new]" in rows[0]["cmd"]:
                break
        else:
            self.fail("could not catch a process being born inside the interval")
        r = rows[0]
        self.assertEqual(r["cpu"], 0.0)
        self.assertTrue(r["cmd"].endswith("... [new]"), r["cmd"])
        self.assertLessEqual(len(r["cmd"]), 44, "command cell is 44 characters wide")
        self.assertEqual(len(r["line"]), 88, "row shifted: %r" % r["line"])

    def test_new_tag_on_short_command(self):
        for attempt in range(3):
            with Fixture("spawn-late", 4, 350, "z", cwd=BUILD, exe="./helper") as fx:
                t, _ = self.table("-n", "100000", "-I", "-i", "1")
                child = fx.read_info("child")
            rows = t.by_pid(child) if child else []
            if rows and "[new]" in rows[0]["cmd"]:
                break
        else:
            self.fail("could not catch a process being born inside the interval")
        self.assertEqual(rows[0]["cmd"], "./helper sleep 4 z [new]")
        self.assertEqual(len(rows[0]["line"]), 88)

    # ───────────────────────── terminal handling ────────────────────────────

    def test_B10_header_labels_sit_over_their_columns(self):
        t, _ = self.table("-n", "3", "-i", "0.1")
        h = t.header
        self.assertEqual(h[:7], "    PID")
        self.assertEqual(h[9:16], "COMMAND")
        # numeric columns are right-justified, and so must be their labels
        self.assertEqual(h[56:62], "  USR%")
        self.assertEqual(h[64:70], "  SYS%")
        self.assertEqual(h[72:78], "  CPU%")
        self.assertEqual(h[80:88], "     RSS")
        self.assertEqual(h[90:102], "     IO_RD/s")
        self.assertEqual(h[104:116], "     IO_WR/s")
        self.assertEqual(h, h.rstrip(), "trailing blanks after the last label")

    def test_no_colour_when_piped(self):
        _, raw = self.table("-n", "5", "-i", "0.1")
        self.assertNotIn(ESC, raw)

    def test_colour_on_a_terminal(self):
        out, rc = self.run_on_pty("-n", "5", "-i", "0.2", seconds=5)
        self.assertEqual(rc, 0)
        self.assertIn(b"\x1b[1m", out, "bold header")
        self.assertIn(b"\x1b[0m", out)
        self.assertRegex(out, rb"\x1b\[3[123]m", "row colour")

    def test_continuous_mode_repeats_until_sigint(self):
        proc = subprocess.Popen([self.exe, "-c", "-n", "3", "-I", "-i", "0.2"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        time.sleep(1.3)
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertGreaterEqual(out.count(b"CPU cores"), 3)

    def test_B8_continuous_mode_keeps_pipes_clean(self):
        proc = subprocess.Popen([self.exe, "-c", "-n", "3", "-I", "-i", "0.2"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        time.sleep(0.7)
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=5)
        self.assertGreaterEqual(out.count(b"CPU cores"), 2)
        self.assertNotIn(b"\x1b[2J", out, "clear-screen sequence written to a pipe")
        self.assertNotIn(ESC, out)

    def test_continuous_mode_clears_a_terminal(self):
        out, rc = self.run_on_pty("-c", "-n", "3", "-i", "0.2", seconds=0.8)
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(out.count(b"\x1b[2J\x1b[H"), 2)

    def test_signal_ends_a_long_sleep_promptly(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            proc = subprocess.Popen([self.exe, "-n", "3", "-i", "30"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.4)
            t0 = time.time()
            proc.send_signal(sig)
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                self.fail("did not stop within 3 s of signal %d" % sig)
            self.assertLess(time.time() - t0, 1.0)
            self.assertEqual(proc.returncode, 0)

    # ──────────────────────── argument validation ───────────────────────────

    BAD_ARGS = [
        ["-n", "abc"], ["-n", "0"], ["-n", "-3"], ["-n", "5x"], ["-n", ""],
        ["-n", "99999999999"],
        ["-i", "abc"], ["-i", "-1"], ["-i", "0"], ["-i", "0.001"], ["-i", "nan"],
        ["-i", "inf"], ["-i", "1e3"], ["-i", "1.2.3"], ["-i", ""],
        ["-p", "abc"], ["-p", "0"], ["-p", "-5"], ["-p", "12abc"],
        ["stray-word"], ["-Z"], ["-n"], ["-i"], ["-p"],
    ]

    def test_B4_bad_arguments_are_rejected(self):
        accepted = []
        for args in self.BAD_ARGS:
            try:
                res = self.run_raw(*args, timeout=3)
            except subprocess.TimeoutExpired:
                accepted.append("%s (ran until killed)" % " ".join(args))
                continue
            if res.returncode == 0 or b"CPU cores" in res.stdout or not res.stderr:
                accepted.append(" ".join(args))
        self.assertEqual(accepted, [], "accepted instead of rejected")

    def test_B4_smallest_interval_is_accepted(self):
        t0 = time.time()
        t, _ = self.table("-n", "3", "-I", "-i", "0.01")
        dt = time.time() - t0
        self.assertEqual(len(t.rows), 3)
        self.assertLess(dt, 0.6, "-i 0.01 took %.2f s" % dt)

    def test_B4_non_finite_interval_does_not_spin(self):
        for value in ("nan", "inf"):
            proc = subprocess.Popen([self.exe, "-c", "-n", "1", "-I", "-i", value],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            try:
                out, _ = proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
            frames = out.count(b"CPU cores")
            self.assertEqual(frames, 0, "-c -i %s printed %d frames in one second" % (value, frames))
            self.assertNotEqual(proc.returncode, 0)


class LibcBuild(Common, unittest.TestCase):
    NAME = "getpid"


class RawBuild(Common, unittest.TestCase):
    NAME = "getpid_raw"

    def test_version(self):
        res = self.run_raw("-v")
        self.assertEqual(res.returncode, 0)
        self.assertRegex((res.stdout + res.stderr).decode(), r"getpid \d+\.\d+\.\d+")

    def test_binary_is_static_and_self_contained(self):
        with open(self.exe, "rb") as f:
            data = f.read()
        self.assertEqual(data[:4], b"\x7fELF")
        phoff, = struct.unpack_from("<Q", data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
        types = [struct.unpack_from("<I", data, phoff + i * phentsize)[0] for i in range(phnum)]
        self.assertNotIn(3, types, "PT_INTERP: needs a dynamic loader")
        self.assertNotIn(2, types, "PT_DYNAMIC: dynamically linked")

    def test_B12_missing_proc_is_reported(self):
        probe = subprocess.run(["unshare", "-r", "true"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        if probe.returncode != 0:
            self.skipTest("unprivileged user namespaces are not available")
        root = os.path.join(BUILD, "empty-root")
        os.makedirs(root, exist_ok=True)
        target = os.path.join(root, "getpid_raw")
        with open(self.exe, "rb") as src, open(target, "wb") as dst:
            dst.write(src.read())
        os.chmod(target, 0o755)
        try:
            res = subprocess.run(["unshare", "-r", "chroot", root, "/getpid_raw", "-n", "3",
                                  "-I", "-i", "0.1"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        finally:
            os.unlink(target)
            os.rmdir(root)
        self.assertNotEqual(res.returncode, 0, "exit status without /proc")
        self.assertIn(b"/proc", res.stderr)
        self.assertNotIn(b"COMMAND", res.stdout, "no empty table expected")


if __name__ == "__main__":
    for needed in ("getpid", "getpid_raw", "helper"):
        if not os.access(os.path.join(BUILD, needed), os.X_OK):
            sys.exit("missing %s — run `make -C tests` first" % os.path.join(BUILD, needed))
    unittest.main(verbosity=2)
