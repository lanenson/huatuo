#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

"""Produce monotonic diskstats input and regular-file activity; Shell asserts."""
import os
import sys
import time

fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
try:
    tick = 0
    while True:
        tick += 1
        # Each read completes in 200ms. A five-second sample therefore crosses
        # the real detector's default await threshold without loading a disk.
        values = [tick, 0, tick * 8, tick * 200,
                  tick, 0, tick * 8, tick * 200,
                  0, tick * 200, tick * 200]
        row = "{} {} {} {}\n".format(sys.argv[2], sys.argv[3], sys.argv[4], " ".join(map(str, values)))
        os.pwrite(fd, row.encode().ljust(512, b" "), 0)
        os.pread(fd, 512, 0)
        time.sleep(0.2)
finally:
    os.close(fd)
