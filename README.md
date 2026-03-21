# getpid

**syscall Linux process inspector**

`getpid` is a minimalistic process monitoring utility for x86_64 Linux. It is implemented entirely via direct system calls, bypassing the C standard library (`libc`), `crt0`, and the dynamic linker.

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

## Build Instructions

Compilation requires a compiler configured for freestanding execution. Using `musl-gcc` is recommended to properly exclude standard startup files:

```sh
musl-gcc -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
  -nostdlib -nostartfiles -static -ffreestanding \
  -o getpid_raw getpid_raw.c -lgcc
```

## Usage

```sh
./getpid_raw [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-n N` | Display top N processes (default: 20) |
| `-i SEC` | Set sampling interval in seconds (default: 1.0) |
| `-t` | Display individual threads (TID) |
| `-p PID` | Monitor a specific PID (implies `-t`) |
| `-k` | Exclude kernel threads from output |
| `-I` | Exclude disk I/O statistics |
| `-c` | Enable continuous refresh mode (SIGINT to terminate) |
| `-v` | Display version information |
| `-h` | Display help output |
