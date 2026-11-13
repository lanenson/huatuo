#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

"""Generate controlled file calls; the Shell test owns all result assertions.

The parent gates activity through pipes so imports, setup and diagnostic output
cannot contribute regular-file IO during the measured interval.
"""

import json
import os
import resource
import signal
import sys
import time


BLOCK_SIZE = 4096
FILE_SIZE = 2 * BLOCK_SIZE
TAIL_SIZE = 17
clock_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1000000000))


def run(fd, iterations):
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
    for _ in range(iterations):
        record("write", BLOCK_SIZE, lambda: os.pwrite(fd, data, 0))
        record("read", BLOCK_SIZE, lambda: os.pread(fd, BLOCK_SIZE, 0))
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


def main():
    fd = os.open(sys.argv[1], os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)
    try:
        os.pwrite(fd, b"s" * FILE_SIZE, 0)
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
            if len(fields) != 2 or fields[0] != "run":
                raise ValueError("expected run <iterations> or stop")
            print(json.dumps(run(fd, int(fields[1]))), flush=True)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
