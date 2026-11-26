#!/usr/bin/env python3
"""Builds a CD image with everything `fresh-install-scan` needs.

A virtual machine that has just been installed has no network, no shared
folder and no guest tools, and the point of scanning it is that it stays
that way. A CD image is the one thing every hypervisor can hand to it. This
script puts four files on one: the Windows build of Warden, a rule bundle,
and the two scripts from `scripts/win/`.

    pip install pycdlib
    python3 scripts/make-scan-kit.py --warden target/release/warden.exe \\
        --rules rules/vendor/rules.wrb --out rules/vendor/warden-kit.iso

`--control` adds a fifth file: a bundle built with `warden rules build
--plain`, which holds its rules as they are. The scan does not use it. The
script on the kit only asks whether it can be read, so that one run shows
whether the machine's antivirus tells it from the bundle under the cipher.

`--dummy` adds what the second run on such a machine needs, the one that
shows Warden removing autostart entries and putting them back: the harmless
stand-in `warden-dummy.exe` and the script `autostart-remedy`. `--tests`
adds the automated tests of the Windows side as a program, for that script
to run at its end:

    cargo build --release -p warden-cli -p warden-dummy
    python3 scripts/make-scan-kit.py --warden target/release/warden.exe \\
        --rules rules/vendor/rules.wrb --dummy target/release/warden-dummy.exe \\
        --out rules/vendor/warden-kit.iso

Keep the image where the bundle is. It holds the bundle, and an antivirus
that takes a bundle for malware may take the image for it too: see
docs/RULES.md, "Rule files and your antivirus".

Attach the image to the machine's CD drive, open the drive there, right-click
`fresh-install-scan.cmd` and choose "Run as administrator".
"""

import argparse
import hashlib
import sys
from pathlib import Path

try:
    import pycdlib
except ImportError:
    sys.exit("This script needs pycdlib: pip install pycdlib")

SCRIPTS = Path(__file__).resolve().parent / "win"


def iso_name(name: str) -> str:
    """The name a file gets in the old ISO 9660 directory; Windows reads the
    Joliet directory next to it, which keeps the real name."""
    stem, _, extension = name.rpartition(".")
    clean = "".join(c if c.isalnum() else "_" for c in stem).upper()[:26]
    return f"/{clean}.{extension.upper()[:3]};1"


def bundle_version(path: Path):
    """The format version in a rule bundle's header, or None if the file is
    not a rule bundle: 1 holds the rules as they are, 2 under a cipher."""
    header = path.read_bytes()[:12]
    if len(header) < 12 or header[:8] != b"WRDNRUL\0":
        return None
    return int.from_bytes(header[8:12], "little")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--warden", required=True, type=Path, help="warden.exe, built for Windows")
    parser.add_argument("--rules", required=True, type=Path, help="the rule bundle to scan with")
    parser.add_argument(
        "--control",
        type=Path,
        help="a bundle built with --plain, to see whether the machine's antivirus blocks it",
    )
    parser.add_argument(
        "--dummy",
        type=Path,
        help="warden-dummy.exe, built for Windows: adds it and the autostart-remedy script",
    )
    parser.add_argument(
        "--tests",
        type=Path,
        help="the tests of warden-autostart built as a program, for autostart-remedy to run",
    )
    parser.add_argument("--out", required=True, type=Path, help="the CD image to write")
    args = parser.parse_args()
    if args.tests is not None and args.dummy is None:
        sys.exit("--tests: only the autostart-remedy script runs them, and --dummy adds that")

    files = {
        "warden.exe": args.warden,
        "rules.wrb": args.rules,
        "fresh-install-scan.cmd": SCRIPTS / "fresh-install-scan.cmd",
        "fresh-install-scan.ps1": SCRIPTS / "fresh-install-scan.ps1",
    }
    if args.control is not None:
        files["rules-plain.wrb"] = args.control
    if args.dummy is not None:
        files["warden-dummy.exe"] = args.dummy
        files["autostart-remedy.cmd"] = SCRIPTS / "autostart-remedy.cmd"
        files["autostart-remedy.ps1"] = SCRIPTS / "autostart-remedy.ps1"
    if args.tests is not None:
        files["autostart-tests.exe"] = args.tests
    for name, path in files.items():
        if not path.is_file():
            sys.exit(f"{name}: {path} is not a file")
    # A control that is itself under the cipher would show nothing.
    if args.control is not None and bundle_version(args.control) != 1:
        sys.exit(f"--control: {args.control} is not a bundle that holds its rules as they are")

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident="WARDEN_KIT")
    for name, path in files.items():
        iso.add_file(str(path), iso_path=iso_name(name), joliet_path=f"/{name}")
    iso.write(str(args.out))
    iso.close()

    kinds = {1: "rules as they are", 2: "rules under a cipher"}
    for name, path in files.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        version = bundle_version(path) if name.endswith(".wrb") else None
        kind = f"  (bundle format {version}, {kinds.get(version, 'unknown')})" if version else ""
        print(f"{digest}  {name}{kind}")
    print(f"Wrote {args.out} ({args.out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
