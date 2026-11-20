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

Keep the image where the bundle is. It holds the bundle, and an antivirus
that takes the bundle for malware may take the image for it too: see
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--warden", required=True, type=Path, help="warden.exe, built for Windows")
    parser.add_argument("--rules", required=True, type=Path, help="the rule bundle to scan with")
    parser.add_argument("--out", required=True, type=Path, help="the CD image to write")
    args = parser.parse_args()

    files = {
        "warden.exe": args.warden,
        "rules.wrb": args.rules,
        "fresh-install-scan.cmd": SCRIPTS / "fresh-install-scan.cmd",
        "fresh-install-scan.ps1": SCRIPTS / "fresh-install-scan.ps1",
    }
    for name, path in files.items():
        if not path.is_file():
            sys.exit(f"{name}: {path} is not a file")

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident="WARDEN_KIT")
    for name, path in files.items():
        iso.add_file(str(path), iso_path=iso_name(name), joliet_path=f"/{name}")
    iso.write(str(args.out))
    iso.close()

    for name, path in files.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"{digest}  {name}")
    print(f"Wrote {args.out} ({args.out.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
