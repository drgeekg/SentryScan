#!/usr/bin/env python3
"""SentryScan Assignment Packager.

Builds reproducible submission ZIP archives directly from immutable Git tags.
Excludes uncommitted working files, virtual environments, local keys, and caches.
Computes and verifies SHA-256 integrity checksums.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"


def run_cmd(cmd: list[str], cwd: Path = REPO_ROOT) -> str:
    """Run a subprocess command and return decoded stdout, exiting on failure."""
    try:
        res = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )
        return res.stdout.strip()
    except subprocess.CalledProcessError as err:
        sys.stderr.write(f"Error executing {' '.join(cmd)}:\n{err.stderr}\n")
        sys.exit(1)


def compute_sha256(filepath: Path) -> str:
    """Compute the SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_archive(archive_path: Path, prefix: str) -> int:
    """Verify ZIP contents, ensuring it contains tracked files and prefix."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        file_list = zf.namelist()
        if not file_list:
            sys.stderr.write(f"Verification Error: {archive_path.name} is empty!\n")
            sys.exit(1)
        for name in file_list:
            if not name.startswith(prefix):
                sys.stderr.write(
                    f"Warning: Member {name} does not start with expected prefix {prefix}\n"
                )
    return len(file_list)


def package_tag(tag: str, output_name: str | None = None) -> Path:
    """Archive a git tag to a zip file in dist/ and write checksum file."""
    # 1. Verify tag exists
    existing_tags = run_cmd(["git", "tag", "-l", tag]).splitlines()
    if tag not in existing_tags:
        sys.stderr.write(f"Error: Git tag '{tag}' does not exist!\n")
        sys.exit(1)

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Compute archive naming and prefix
    clean_tag = tag.replace("-", "_").replace(".", "_")
    prefix = f"SentryScan_{clean_tag}/"
    archive_filename = output_name or f"SentryScan_{clean_tag}.zip"
    archive_path = DIST_DIR / archive_filename

    if archive_path.exists():
        archive_path.unlink()

    # 3. Create archive using git archive
    print(f"[*] Packaging tag '{tag}' into '{archive_path.name}'...")
    run_cmd(
        [
            "git",
            "archive",
            "--format=zip",
            f"--prefix={prefix}",
            f"--output={archive_path}",
            tag,
        ]
    )

    # 4. Verify archive
    member_count = verify_archive(archive_path, prefix)
    sha256_hash = compute_sha256(archive_path)

    # 5. Write checksum file
    checksum_path = DIST_DIR / f"{archive_filename}.sha256"
    checksum_path.write_text(f"{sha256_hash}  {archive_filename}\n", encoding="utf-8")

    print(f"[+] Archive generated: {archive_path}")
    print(f"[+] Members packed:    {member_count} files")
    print(f"[+] SHA-256 Checksum:  {sha256_hash}")
    print(f"[+] Checksum manifest: {checksum_path.name}")
    return archive_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Package SentryScan git tag into submission archive."
    )
    parser.add_argument("tag", help="Git tag name (e.g. p0-baseline, assignment-1.1)")
    parser.add_argument("--output", "-o", help="Custom output filename in dist/")
    args = parser.parse_args()

    package_tag(args.tag, args.output)


if __name__ == "__main__":
    main()
