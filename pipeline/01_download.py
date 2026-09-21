#!/usr/bin/env python3
"""
Download the scan dump to disk, resumably, and verify it is complete.

Why to disk rather than straight into the pipe: the archive is a *single* zstd
frame, so decompression cannot resume from the middle. A dropped connection
half way through therefore costs the entire run -- and worse, fails silently:
zstd stops, the reader sees a clean end-of-stream, and you get a plausible
looking result built from half the data.

That happened. This script exists so it cannot happen again:

  * --continue-at resumes a partial download instead of restarting
  * --retry survives transient drops
  * the final size is checked against Content-Length before anything downstream
    is allowed to run

Usage:
    python3 pipeline/01_download.py [dest]
"""
import os
import subprocess
import time
import sys

URL = (
    "https://f001.backblazeb2.com/b2api/v1/b2_download_file_by_id"
    "?fileId=4_z53658c377a6f469082f90a15_f21924b729484966a"
    "_d20260914_m111636_c001_v0001150_t0059_u01789384596114"
)


def expected_size(url: str) -> int:
    out = subprocess.run(
        ["curl", "-sIL", url], capture_output=True, text=True, check=True
    ).stdout
    for line in out.splitlines():
        if line.lower().startswith("content-length:"):
            return int(line.split(":", 1)[1].strip())
    raise RuntimeError("server did not report Content-Length")


def main(dest: str) -> int:
    want = expected_size(URL)
    have = os.path.getsize(dest) if os.path.exists(dest) else 0
    print(f"expected {want:,} bytes; have {have:,} ({have / want * 100:.1f}%)")

    # Retry OUTSIDE curl, not inside it.
    #
    # `curl --retry N --continue-at -` resolves the resume offset once, when it
    # starts. Every internal retry then restarts from that original offset and
    # truncates whatever was downloaded since -- so a drop at 2.5 GB throws
    # 2.5 GB away and begins again, forever. Observed exactly that.
    #
    # Running curl afresh per attempt makes it re-read the file size, so each
    # attempt resumes from where the last one actually stopped.
    attempt = 0
    while have < want and attempt < 40:
        attempt += 1
        print(f"attempt {attempt}: resuming at {have:,} "
              f"({have / want * 100:.1f}%) ...")
        subprocess.run([
            "curl", "-L",
            "--continue-at", "-",
            "--fail",
            "--connect-timeout", "30",
            "--speed-limit", "10000",   # < 10 KB/s for 60s == stalled, give up
            "--speed-time", "60",
            "-o", dest, URL,
        ])
        now = os.path.getsize(dest) if os.path.exists(dest) else 0
        if now <= have:
            print(f"  no progress ({now:,} bytes) -- backing off", file=sys.stderr)
            time.sleep(min(60, 5 * attempt))
        have = now

    got = os.path.getsize(dest) if os.path.exists(dest) else 0
    if got != want:
        print(f"\nINCOMPLETE: {got:,} of {want:,} bytes "
              f"({got / want * 100:.1f}%). Re-run to resume.", file=sys.stderr)
        return 1

    print(f"\nOK: {got:,} bytes, complete. Safe to decompress.")
    return 0


if __name__ == "__main__":
    raise SystemExit(
        main(sys.argv[1] if len(sys.argv) > 1 else "data/raw/scan.zst")
    )
