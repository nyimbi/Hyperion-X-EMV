"""Small standard-library helper CLI for bundle/report automation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def write_submission_index(root: Path, out: Path) -> None:
    files = [
        {
            "path": file.relative_to(root).as_posix(),
            "size_bytes": file.stat().st_size,
            "sha256": sha256_file(file),
        }
        for file in iter_files(root)
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "type": "hyperion-python-submission-index",
                "root": str(root),
                "files": files,
                "boundary": "hash inventory only; certification acceptance remains external",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hyperion-tools")
    sub = parser.add_subparsers(dest="command", required=True)
    index = sub.add_parser("index", help="hash a generated submission directory")
    index.add_argument("--root", required=True, type=Path)
    index.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "index":
        write_submission_index(args.root, args.out)
        print(args.out)
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
