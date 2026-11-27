#!/usr/bin/env python3
"""Reads what a restart study wrote to the serial port, and times its restarts.

`scripts/win/restart-study.ps1` restarts a virtual machine again and again.
Before each restart it writes a line to the serial port, and one when it
runs again; in between, the machine's firmware writes to the same port when
the machine starts. The hypervisor captures the port to a file on the host,
and `watch-serial-capture.py` notes when that file grew. This script lays
the two side by side:

    python3 scripts/read-restart-study.py target/vm/com1.txt \\
        --watch target/vm/com1-watch.log --out target/vm/restart-study

For each round it says how long the machine took from the request for a
restart to the firmware's first sign of life, and from there until the
script ran again. It adds what Windows wrote down about the shutdown and
the start, which the study passes on, and whether somebody noted that the
machine was reset by hand. It writes `restart-study-timed.json`, a table as
text, and the result file that the study itself sent at its end.

Without `--watch` there are no times from outside, and the rest is still
read. Only the last study in the capture is read.

The times in the capture are the machine's own. Its clock is set anew at
every start, so they are shown and never subtracted across a restart.
"""

import argparse
import base64
import bisect
import datetime
import hashlib
import json
import re
import statistics
import sys
from pathlib import Path

# What the firmware of a VirtualBox machine writes to the serial port when
# the machine starts: it clears the screen of a terminal, three times.
FIRMWARE = b"\x1b[2J\x1b[01;01H\x1b[=3h\x1b[2J\x1b[01;01H"
LINE = re.compile(rb"WARDEN-STUDY ([A-Z]+)(?: (.*))?$")
BEGIN = re.compile(rb"-----BEGIN WARDEN FILE (\S+) sha256=([0-9a-f]{64}) bytes=(\d+)-----")
PAIR = re.compile(r"(\w+)=(\S+)")


def parse_time(text: str) -> float:
    """A time as the watcher and the study write it, in seconds since the epoch."""
    for form in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            moment = datetime.datetime.strptime(text, form)
            return moment.replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError(f"not a time: {text}")


def show_time(seconds):
    if seconds is None:
        return None
    moment = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class Watch:
    """When the capture had reached which size, from the watcher's log."""

    def __init__(self, path):
        self.sizes = []  # the sizes the capture was seen at, rising
        self.seen = []  # for each: (not before, not after), seconds since the epoch
        self.notes = []  # (time, text)
        if path is None:
            return
        last_time = None
        last_size = 0
        for raw in path.read_text(encoding="ascii", errors="replace").splitlines():
            parts = raw.split(" ", 2)
            if len(parts) < 3:
                continue
            try:
                at = parse_time(parts[0])
                size = int(parts[1])
            except ValueError:
                continue
            word = parts[2]
            if word.startswith("note"):
                self.notes.append((at, word[4:].strip()))
                continue
            if size < last_size:
                # A capture that was begun anew: what was noted before is
                # about another file.
                self.sizes, self.seen, self.notes = [], [], []
                last_time = None
                last_size = 0
            if size > last_size:
                not_after = at
                not_before = last_time if last_time is not None else at
                written = re.search(r"mtime=(\S+)", word)
                looked = re.search(r"looked=([0-9.]+)", word)
                if word.startswith("start") and written and written.group(1) != "unknown":
                    # It grew while nobody was looking. The file's own time
                    # says when it was last written to.
                    not_after = min(at, parse_time(written.group(1)))
                elif looked:
                    # The watcher had looked that many seconds before.
                    not_before = at - float(looked.group(1))
                self.sizes.append(size)
                self.seen.append((min(not_before, not_after), not_after))
            last_time = at
            last_size = size

    def when(self, offset):
        """When the capture first held `offset` bytes: (not before, not
        after), or None if the watcher never saw it that large."""
        at = bisect.bisect_left(self.sizes, offset)
        if at >= len(self.sizes):
            return None
        return self.seen[at]


def read_capture(data: bytes):
    """The lines of the last study with where each ends in the capture, the
    places where the firmware wrote, and the files that were sent."""
    lines = []  # (word, text, offset of the line's end)
    files = {}
    starts = []  # offsets of the firmware's first byte, one for each start
    at = 0
    last_end = None
    while True:
        found = data.find(FIRMWARE, at)
        if found < 0:
            break
        if last_end is None or found - last_end > 64:
            starts.append(found)
        last_end = found + len(FIRMWARE)
        at = last_end

    offset = 0
    in_file = None
    for raw in data.split(b"\n"):
        end = offset + len(raw) + 1
        offset = end
        text = raw.replace(FIRMWARE, b"").rstrip(b"\r")
        begin = BEGIN.search(text)
        if begin:
            in_file = (begin.group(1).decode("ascii"), begin.group(2).decode("ascii"), [])
            continue
        if in_file is not None:
            if text.startswith(b"-----END WARDEN FILE"):
                name, digest, chunks = in_file
                try:
                    content = base64.b64decode(b"".join(chunks), validate=True)
                    if hashlib.sha256(content).hexdigest() == digest:
                        files[name] = content
                except (ValueError, base64.binascii.Error):
                    pass
                in_file = None
            else:
                in_file[2].append(text.strip())
            continue
        found = LINE.search(text)
        if found:
            rest = (found.group(2) or b"").decode("latin-1")
            lines.append((found.group(1).decode("ascii"), rest, min(end, len(data))))

    # Only the last study.
    first = 0
    for index, (word, _, _) in enumerate(lines):
        if word == "START":
            first = index
    lines = lines[first:]
    begun = lines[0][2] if lines else 0
    starts = [start for start in starts if start >= begun]
    return lines, starts, files


def pairs(text: str) -> dict:
    return dict(PAIR.findall(text))


def fields_of(text: str) -> dict:
    """The fields of an event that the study passed on: name=value; ..."""
    _, _, tail = text.partition(" fields: ")
    found = {}
    for part in tail.split("; "):
        name, sep, value = part.partition("=")
        if sep:
            found[name.strip()] = value.strip()
    return found


def number(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def study(lines, starts, watch):
    """Everything about each restart, in the order they were asked for."""
    restarts = []  # one for each RESTART line
    by_round = {}
    current = None  # the restart that the machine last came back from
    acted = {}
    info = {"start": None, "machine": None, "schedule": [], "done": None, "failed": [], "notes": []}
    shutdowns, boots = [], []  # events 200 and 100, in order
    for word, text, end in lines:
        values = pairs(text)
        if word == "START":
            info["start"] = text
        elif word == "MACHINE":
            info["machine"] = text
        elif word == "SCHEDULE":
            info["schedule"] = text.split(",")
        elif word == "ACTED":
            acted[number(values.get("round"))] = values
        elif word == "RESTART":
            entry = {
                "round": number(values.get("round")),
                "kind": values.get("kind"),
                "rehearsal": text.endswith("rehearsal"),
                "asked_guest": values.get("guest"),
                "asked_up_ms": number(values.get("up")),
                "asked_offset": end,
                "back_offset": None,
                "back_guest": None,
                "back_up_ms": None,
                "firmware_offset": None,
                "events_noted": [],
            }
            done = acted.get(entry["round"])
            if done:
                entry["exit"] = number(done.get("exit"))
                entry["action_seconds"] = float(done.get("seconds", "nan"))
            restarts.append(entry)
            by_round[entry["round"]] = entry
        elif word == "BACK":
            current = by_round.get(number(values.get("round")))
            if current is not None and current["back_offset"] is None:
                current["back_offset"] = end
                current["back_guest"] = values.get("guest")
                current["back_up_ms"] = number(values.get("up"))
        elif word == "EVENT":
            log, ident = values.get("log"), number(values.get("id"))
            if log == "performance" and ident == 200:
                shutdowns.append(fields_of(text))
            elif log == "performance" and ident == 100:
                boots.append(fields_of(text))
            elif current is not None:
                current["events_noted"].append(f"{log} {ident}")
        elif word == "DONE":
            info["done"] = text
        elif word == "FAILED":
            info["failed"].append(text)
        elif word == "NOTE":
            info["notes"].append(text)

    # The firmware's sign of life between the request and the return.
    for index, entry in enumerate(restarts):
        after = entry["asked_offset"]
        before = entry["back_offset"]
        if before is None and index + 1 < len(restarts):
            before = restarts[index + 1]["asked_offset"]
        for start in starts:
            if start >= after and (before is None or start < before):
                entry["firmware_offset"] = start
                break

    # What Windows wrote down, in order: the first shutdown it reports
    # after the study began is the first restart, and so on.
    for entry, shutdown in zip(restarts, shutdowns):
        entry["windows_shutdown_ms"] = number(shutdown.get("ShutdownTime"))
        entry["windows_shutdown_degraded"] = shutdown.get("ShutdownIsDegradation")
    for entry, boot in zip(restarts, boots):
        entry["windows_start_ms"] = number(boot.get("BootTime"))
        entry["windows_start_main_path_ms"] = number(boot.get("MainPathBootTime"))
    info["shutdowns_reported"] = len(shutdowns)
    info["starts_reported"] = len(boots)

    # The times from outside.
    for entry in restarts:
        asked = watch.when(entry["asked_offset"])
        firmware = watch.when(entry["firmware_offset"] + 1) if entry["firmware_offset"] is not None else None
        back = watch.when(entry["back_offset"]) if entry["back_offset"] is not None else None
        entry["asked_at"] = show_time(asked[1]) if asked else None
        entry["firmware_at"] = show_time(firmware[1]) if firmware else None
        entry["back_at"] = show_time(back[1]) if back else None
        blur = 0.0
        for seen in (asked, firmware, back):
            if seen:
                blur = max(blur, seen[1] - seen[0])
        entry["times_uncertain_by_seconds"] = round(blur, 1)
        entry["seconds_to_firmware"] = round(firmware[1] - asked[1], 1) if asked and firmware else None
        entry["seconds_firmware_to_back"] = round(back[1] - firmware[1], 1) if firmware and back else None
        entry["seconds_to_back"] = round(back[1] - asked[1], 1) if asked and back else None
        if entry["back_up_ms"] is not None and entry["seconds_firmware_to_back"] is not None:
            # The script says how long Windows had been running when it
            # wrote its line. The rest was before Windows.
            entry["seconds_firmware_to_windows"] = round(
                entry["seconds_firmware_to_back"] - entry["back_up_ms"] / 1000.0, 1
            )
        entry["reset_by_hand"] = False
        if asked:
            until = back[1] if back else None
            for at, text in watch.notes:
                if "reset" in text and at >= asked[1] and (until is None or at <= until):
                    entry["reset_by_hand"] = True
    return info, restarts


def summary(restarts):
    kinds = {}
    for entry in restarts:
        if entry["rehearsal"]:
            continue
        kind = kinds.setdefault(
            entry["kind"], {"restarts": 0, "reset_by_hand": 0, "not_back": 0, "seconds_to_firmware": []}
        )
        kind["restarts"] += 1
        if entry["reset_by_hand"]:
            kind["reset_by_hand"] += 1
        if entry["back_offset"] is None:
            kind["not_back"] += 1
        if entry["seconds_to_firmware"] is not None and not entry["reset_by_hand"]:
            kind["seconds_to_firmware"].append(entry["seconds_to_firmware"])
    for kind in kinds.values():
        times = sorted(kind["seconds_to_firmware"])
        kind["seconds_to_firmware"] = times
        if times:
            kind["shortest"] = times[0]
            kind["median"] = round(statistics.median(times), 1)
            kind["longest"] = times[-1]
    return kinds


def table(restarts, kinds) -> str:
    def cell(value, width):
        return ("-" if value is None else str(value)).rjust(width)

    out = []
    out.append(
        "round  kind      asked at (UTC)            to firmware  firmware to back  of that before Windows"
        "  Windows: shutdown ms  reset by hand"
    )
    for entry in restarts:
        out.append(
            f"{cell(entry['round'], 5)}  {str(entry['kind']).ljust(8)}  {str(entry['asked_at'] or '-').ljust(24)}"
            f"  {cell(entry['seconds_to_firmware'], 9)} s  {cell(entry['seconds_firmware_to_back'], 14)} s"
            f"  {cell(entry.get('seconds_firmware_to_windows'), 20)} s  {cell(entry.get('windows_shutdown_ms'), 19)}"
            f"  {'yes' if entry['reset_by_hand'] else ''}"
        )
    out.append("")
    out.append("kind      restarts  reset by hand  to firmware: shortest  median  longest (without those reset by hand)")
    for name in sorted(kinds):
        kind = kinds[name]
        out.append(
            f"{name.ljust(8)}  {cell(kind['restarts'], 8)}  {cell(kind['reset_by_hand'], 13)}"
            f"  {cell(kind.get('shortest'), 21)}  {cell(kind.get('median'), 6)}  {cell(kind.get('longest'), 7)}"
        )
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture", type=Path, help="the file the serial port was captured to")
    parser.add_argument("--watch", type=Path, help="the log of watch-serial-capture.py")
    parser.add_argument("--out", type=Path, help="a folder for the results")
    args = parser.parse_args()

    data = args.capture.read_bytes()
    lines, starts, files = read_capture(data)
    if not lines:
        sys.exit("No restart study in this capture.")
    watch = Watch(args.watch)
    info, restarts = study(lines, starts, watch)
    kinds = summary(restarts)
    for entry in restarts:
        for key in ("asked_offset", "back_offset", "firmware_offset"):
            entry.pop(key)
    result = {
        "capture_bytes": len(data),
        "capture_sha256": hashlib.sha256(data).hexdigest(),
        "starts_of_the_machine_in_the_study": len(starts),
        "study": info,
        "notes_from_outside": [{"at": show_time(at), "text": text} for at, text in watch.notes],
        "by_kind": kinds,
        "restarts": restarts,
    }
    text = table(restarts, kinds)
    print(text)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "restart-study-timed.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        (args.out / "restart-study-timed.txt").write_text(text, encoding="utf-8")
        for name, content in files.items():
            (args.out / Path(name).name).write_bytes(content)
        print(f"Written to {args.out}")


if __name__ == "__main__":
    main()
