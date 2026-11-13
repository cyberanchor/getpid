# getpid

`getpid` no libc crt Linux x86_64 native syscall procmon

## Features

* **Zero Dependencies:** Operates without `glibc`, `musl`, or dynamic linking. The compiled binary is entirely self-contained.
* **Direct Syscall Invocation:** Standard library functions are replaced with direct kernel interfaces:
  * File I/O: `sys_open`, `sys_read`, `sys_close`
  * Directory Traversal: `sys_getdents64`
  * Memory Management: `sys_brk`
  * Signal Handling: `sys_rt_sigaction`
* **Custom Allocator:** Utilizes a bump-pointer arena allocator over `sys_brk` for $O(1)$ allocations with zero memory fragmentation during the sampling loop.
* **Fixed-Point Arithmetic:** Calculates CPU utilization strictly using integer arithmetic to avoid FPU context switching and library dependencies.
* **Buffered I/O:** Implements a custom 8KB output buffer to minimize `sys_write` overhead.

## Compilation

```sh
musl-gcc -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
  -nostdlib -nostartfiles -static -ffreestanding \
  -o getpid_raw getpid_raw.c -lgcc
```

`getpid.c` is the same tool written against libc. It takes the same options, except `-v`:

```sh
gcc -O2 -Wall -Wextra -pedantic -std=gnu11 -o getpid getpid.c
```

## Usage

```sh
./getpid_raw [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-n N` | Display top N processes (default: 20) |
| `-i SEC` | Set sampling interval in seconds (default: 1.0, minimum: 0.01) |
| `-t` | Display individual threads (TID) |
| `-p PID` | Monitor a specific process, given by its PID or any of its thread IDs (implies `-t`) |
| `-k` | Exclude kernel threads from output |
| `-I` | Exclude disk I/O statistics |
| `-c` | Enable continuous refresh mode (SIGINT to terminate) |
| `-v` | Display version information |
| `-h` | Display help output |

### Notes

* Command names are printed with every byte outside printable ASCII replaced by `?`, so a process cannot inject terminal escape sequences or forge table rows.
* A process that was not there at the start of the sampling interval, including one that reuses a recycled PID, is tagged `[new]` and shown with 0% CPU for that interval.
* Colors and screen clearing are used only when the output is a terminal; output redirected to a file or a pipe stays plain text.
* The exit status is 1 on invalid options, when the `-p` target does not exist or exits, and when `/proc` cannot be read.

## Tests

```sh
make -C tests
```

Builds both programs and runs unit tests for their internals plus end-to-end tests against the live `/proc`. Requires `gcc`, `make` and `python3`.
