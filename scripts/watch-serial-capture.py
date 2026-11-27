#!/usr/bin/env python3
"""Writes down when a file grew, by the clock of the machine this runs on.

A virtual machine's serial port can be captured to a file on the host. What
the machine writes there has only the machine's own times in it, and the
machine's clock is set anew at every start. The restart study wants to know
how long a restart took, so somebody outside has to look at a clock that
keeps running. This script is that somebody: several times a second it looks
at the size of the capture, and it notes every change with the time.

    python3 scripts/watch-serial-capture.py target/vm/com1.txt \\
        --log target/vm/com1-watch.log --seconds 170

Each line of the log has a time in UTC, the size of the capture in bytes at
that time, and a word about the line:

    2026-11-27T23:05:17.250Z 18230 grew looked=0.2
    2026-11-27T23:07:55.100Z 18230 end
    2026-11-27T23:07:59.004Z 18317 start mtime=2026-11-27T23:07:41.512Z
    2026-11-27T23:09:12.731Z 18317 note reset by hand

"grew" says how many seconds before that the script had last looked, so the
capture grew within that time. "end" is the last look of a run of this
script and "start" the first look of the next, with the time the file was
last written to: if the capture grew while nobody was looking, that time is
all that is known about when. "shrank" is a capture that was begun anew, as
VirtualBox does when a machine is powered on. `--note` adds a line with
some words and ends.

The script reads the file's size and nothing else, and writes only to its
log. `read-restart-study.py` reads the log together with the capture.
"""

import argparse
import datetime
import os
import sys
import time
from pathlib import Path


def stamp(seconds: float) -> str:
    """A time since the epoch as UTC to the millisecond."""
    moment = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def size_of(path: Path) -> int:
    """The size of the file, or -1 if it is not there. Asked of the file
    itself and not of its folder, which may answer from memory."""
    try:
        with open(path, "rb") as file:
            return file.seek(0, os.SEEK_END)
    except OSError:
        return -1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture", type=Path, help="the file the serial port is captured to")
    parser.add_argument("--log", required=True, type=Path, help="the log to add lines to")
    parser.add_argument("--seconds", type=float, default=170.0, help="how long to watch")
    parser.add_argument("--interval", type=float, default=0.2, help="seconds between two looks")
    parser.add_argument("--note", help="add a line with this text and end")
    args = parser.parse_args()

    with open(args.log, "a", encoding="ascii", errors="replace") as log:

        def write(seconds: float, size: int, word: str) -> None:
            line = f"{stamp(seconds)} {size} {word}"
            log.write(line + "\n")
            log.flush()
            print(line)

        size = size_of(args.capture)
        if args.note is not None:
            write(time.time(), size, "note " + " ".join(args.note.split()))
            return
        try:
            written = stamp(args.capture.stat().st_mtime)
        except OSError:
            written = "unknown"
        write(time.time(), size, f"start mtime={written}")
        looked = time.monotonic()
        until = looked + args.seconds
        while time.monotonic() < until:
            time.sleep(args.interval)
            now = size_of(args.capture)
            since = time.monotonic() - looked
            looked += since
            if now != size:
                write(time.time(), now, f"{'grew' if now > size else 'shrank'} looked={since:.1f}")
                size = now
        write(time.time(), size, "end")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
