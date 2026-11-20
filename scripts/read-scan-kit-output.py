#!/usr/bin/env python3
"""Reads what `fresh-install-scan` sent through the serial port.

A virtual machine without a network hands its results to the host through
its serial port, which the hypervisor connects to a file. This script takes
that file apart again: it prints the progress lines, writes out each file
that was sent, and checks every file against the SHA-256 and the length
that came with it.

    python3 scripts/read-scan-kit-output.py com1.txt --out results/

The capture may hold other text, such as messages of the machine's firmware,
and more than one run. Only the last run is read. The exit code is 0 when
that run finished and every file in it arrived whole.
"""

import argparse
import base64
import binascii
import hashlib
import re
import sys
from pathlib import Path

MARK = "WARDEN-KIT "
BEGIN = re.compile(r"-----BEGIN WARDEN FILE (\S+) sha256=([0-9a-f]{64}) bytes=(\d+)-----")
END = re.compile(r"-----END WARDEN FILE (\S+)-----")
# A file name as the kit writes it: no folders, nothing that leaves `--out`.
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def last_run(lines):
    """The lines from the last START marker on."""
    starts = [i for i, line in enumerate(lines) if (MARK + "START") in line]
    return lines[starts[-1]:] if starts else []


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("capture", type=Path, help="the file the serial port was written to")
    parser.add_argument("--out", type=Path, help="folder to write the received files to")
    args = parser.parse_args()

    text = args.capture.read_bytes().decode("ascii", errors="replace")
    lines = last_run(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))
    if not lines:
        sys.exit(f"{args.capture}: no run in it (no line with '{MARK}START')")

    problems = []
    finished = None
    received = 0
    name = expected_hash = expected_bytes = None
    chunks = []
    for line in lines:
        begin = BEGIN.search(line)
        end = END.search(line)
        if begin:
            if name is not None:
                problems.append(f"{name}: a second file starts before this one ended")
            name, expected_hash, expected_bytes = begin.group(1), begin.group(2), int(begin.group(3))
            chunks = []
        elif end:
            if name is None or end.group(1) != name:
                problems.append(f"{end.group(1)}: an end without its beginning")
                continue
            try:
                data = base64.b64decode("".join(chunks), validate=True)
            except (binascii.Error, ValueError) as error:
                problems.append(f"{name}: not valid base64 ({error})")
                name = None
                continue
            actual = hashlib.sha256(data).hexdigest()
            if len(data) != expected_bytes:
                problems.append(f"{name}: {len(data)} bytes arrived, {expected_bytes} were sent")
            elif actual != expected_hash:
                problems.append(f"{name}: SHA-256 is {actual}, sent was {expected_hash}")
            elif not SAFE_NAME.fullmatch(name):
                problems.append(f"{name!r}: not a file name this script writes")
            else:
                received += 1
                print(f"file   {name}: {len(data):,} bytes, sha256 {actual}")
                if args.out:
                    args.out.mkdir(parents=True, exist_ok=True)
                    (args.out / name).write_bytes(data)
            name = None
        elif name is not None:
            chunks.append(line.strip())
        elif MARK in line:
            marker = line[line.index(MARK):].strip()
            print(f"marker {marker}")
            word = marker[len(MARK):].split(" ", 1)[0]
            if word in ("DONE", "FAILED"):
                finished = word

    if name is not None:
        problems.append(f"{name}: the capture ends in the middle of this file")
    if finished is None:
        problems.append("the run did not finish: no DONE and no FAILED line")
    elif finished == "FAILED":
        problems.append("the run says that it failed")
    for problem in problems:
        print(f"PROBLEM {problem}", file=sys.stderr)
    if problems:
        sys.exit(1)
    where = f", written to {args.out}" if args.out else ""
    print(f"The run finished and {received} file(s) arrived whole{where}.")


if __name__ == "__main__":
    main()
