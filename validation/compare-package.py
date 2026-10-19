#!/usr/bin/env python3
"""Assert that a local hotfix changes only the packaged daemon executable."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


def payload(path):
    result = {}
    with subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE) as stream:
        with tarfile.open(fileobj=stream.stdout, mode="r|") as archive:
            for item in archive:
                name = item.name.removeprefix("./").rstrip("/")
                if not name or name in {".PKGINFO", ".BUILDINFO", ".MTREE"}:
                    continue
                digest = None
                if item.isfile():
                    with archive.extractfile(item) as content:
                        digest = hashlib.file_digest(content, "sha256").hexdigest()
                result[name] = (
                    item.type, item.mode, item.uid, item.gid, item.linkname, digest
                )
        if stream.wait() != 0:
            raise RuntimeError("package decompression failed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock", type=Path)
    parser.add_argument("patched", type=Path)
    args = parser.parse_args()
    before, after = payload(args.stock), payload(args.patched)
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = sorted(name for name in before.keys() & after.keys()
                     if before[name] != after[name])
    passed = not added and not removed and changed == ["usr/bin/gnome-keyring-daemon"]
    print(json.dumps({"added": added, "removed": removed, "changed": changed,
                      "stock_entries": len(before), "patched_entries": len(after),
                      "passed": passed}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
