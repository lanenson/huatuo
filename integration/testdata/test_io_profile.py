#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

"""Generate controlled file calls; the Shell test owns all result assertions.

The parent gates activity through pipes so imports, setup and diagnostic output
cannot contribute regular-file IO during the measured interval.
"""

import ctypes
import json
import os
import resource
import signal
import sys
import time


BLOCK_SIZE = 4096
READ_SIZE = 2048
FILE_SIZE = 2 * BLOCK_SIZE
TAIL_SIZE = 17
clock_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1000000000))
wall_clock_ns = getattr(time, "time_ns", lambda: int(time.time() * 1000000000))


def run(fd, iterations, alternate=None):
    results = {direction: {} for direction in ("read", "write")}
    short_calls = {"read": 0, "write": 0}
    error_numbers = {}

    def record(direction, requested, operation):
        try:
            returned = operation()
            size = len(returned) if isinstance(returned, bytes) else returned
            if size > 0:
                outcome = "success"
                if size < requested:
                    short_calls[direction] += 1
            elif requested == 0:
                outcome = "zero_length"
            elif direction == "read":
                outcome = "eof"
            else:
                outcome = "zero_result"
        except OSError as error:
            outcome, size = "error", 0
            key = str(error.errno)
            error_numbers[key] = error_numbers.get(key, 0) + 1
        counters = results[direction].setdefault(outcome, {"bytes": 0, "count": 0})
        counters["bytes"] += size
        counters["count"] += 1

    # Truncation is outside the selected read_iter/write_iter boundaries.
    os.ftruncate(fd, FILE_SIZE)
    data = b"x" * BLOCK_SIZE
    started = clock_ns()
    def write():
        os.lseek(fd, 0, os.SEEK_SET)
        return os.write(fd, data)

    for i in range(iterations):
        if alternate is None or i != alternate:
            record("write", BLOCK_SIZE, lambda: os.pwrite(fd, data, 0))
        else:
            record("write", BLOCK_SIZE, write)
    for _ in range(iterations // 2):
        record("read", READ_SIZE, lambda: os.pread(fd, READ_SIZE, 0))
    record("read", BLOCK_SIZE, lambda: os.pread(fd, BLOCK_SIZE, FILE_SIZE - TAIL_SIZE))
    record("read", BLOCK_SIZE, lambda: os.pread(fd, BLOCK_SIZE, FILE_SIZE))
    record("read", 0, lambda: os.pread(fd, 0, 0))
    record("write", 0, lambda: os.pwrite(fd, b"", 0))
    # generic_write_checks runs inside ext4/XFS write_iter: first a short
    # write reaches RLIMIT_FSIZE, then the next write returns EFBIG there.
    record("write", BLOCK_SIZE, lambda: os.pwrite(fd, data, FILE_SIZE))
    record("write", BLOCK_SIZE, lambda: os.pwrite(fd, data, FILE_SIZE + TAIL_SIZE))
    finished = clock_ns()
    return {
        "started_ns": started,
        "finished_ns": finished,
        "results": results,
        "short_calls": short_calls,
        "error_numbers": error_numbers,
        "elapsed_ns": finished - started,
        "file_size": os.fstat(fd).st_size,
    }


def set_comm(libc, name):
    if libc.prctl(15, ctypes.c_char_p(name.encode()), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NAME")


def time_phase(fd, libc, phase):
    # Distinct system call sites yield distinct stack IDs even without symbols.
    name = "io-phase-%d" % phase
    set_comm(libc, name)
    data = b"x" * BLOCK_SIZE
    os.lseek(fd, 0, os.SEEK_SET)
    write = (
        lambda: os.pwrite(fd, data, 0),
        lambda: os.write(fd, data),
        lambda: os.writev(fd, [data]),
        lambda: os.write(fd, data),
    )[phase]
    started = clock_ns()
    written = write()
    finished = clock_ns()
    read = len(os.pread(fd, READ_SIZE, 0))
    return {
        "comm": name,
        "started_ns": started,
        "finished_ns": finished,
        "results": {
            "write": {"success": {"bytes": written, "count": 1}},
            "read": {"success": {"bytes": read, "count": 1}},
        },
    }


def overflow(fd, keys):
    libc = ctypes.CDLL(None, use_errno=True)
    data = b"x" * 19
    total = 0
    for i in range(keys):
        set_comm(libc, "io-%d" % i)
        total += os.pwrite(fd, data, 0)
    zero_bytes = os.pwrite(fd, b"", 0)
    return {"bytes": total, "count": keys, "zero_bytes": zero_bytes}


def main():
    fd = os.open(sys.argv[1], os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)
    try:
        if sys.argv[2:] == ["stream"]:
            data = b"x" * (128 * 1024)
            while True:
                os.pwrite(fd, data, 0)
                time.sleep(0.005)

        os.pwrite(fd, b"s" * FILE_SIZE, 0)
        blocker = None
        if sys.argv[2:]:
            blocker = ctypes.CDLL(sys.argv[2])
            status = blocker.io_profile_fault_support()
            if status != 0:
                print("io-cutoff-unavailable {}".format(-status), flush=True)
                blocker = None
        libc = ctypes.CDLL(None, use_errno=True)
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        _, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_SIZE + TAIL_SIZE, hard_limit))
        print("io-workload-ready", flush=True)
        for command in sys.stdin:
            fields = command.split()
            if fields == ["stop"]:
                return
            if len(fields) == 2 and fields[0] == "wait":
                time.sleep(max(0, (int(fields[1]) - clock_ns()) / 1000000000))
                print("io-wait-complete", flush=True)
                continue
            if fields == ["blocked-read"]:
                if blocker is None:
                    raise ValueError("blocked-read requires userfaultfd")
                size = blocker.io_profile_blocked_read(fd)
                if size < 0:
                    raise OSError(-size, os.strerror(-size))
                print(json.dumps({"bytes": size, "finished_ns": wall_clock_ns()}), flush=True)
                continue
            if len(fields) == 2 and fields[0] == "time-phase":
                print(json.dumps(time_phase(fd, libc, int(fields[1]))), flush=True)
                continue
            if len(fields) == 2 and fields[0] == "overflow":
                print(json.dumps(overflow(fd, int(fields[1]))), flush=True)
                continue
            if len(fields) not in (2, 3) or fields[0] != "run":
                raise ValueError("expected run <iterations> [alternate write index] or stop")
            alternate = int(fields[2]) if len(fields) == 3 else None
            print(json.dumps(run(fd, int(fields[1]), alternate)), flush=True)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
