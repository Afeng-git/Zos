#!/usr/bin/env python3
"""Small dependency-free newc initramfs reader/writer used by ZOS builds."""
from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path, PurePosixPath


HEADER_SIZE = 110


def _padding(size: int) -> int:
    return (-size) & 3


def _safe_target(root: Path, name: str) -> Path:
    pure = PurePosixPath(name.lstrip("/"))
    if not name or ".." in pure.parts:
        raise ValueError(f"unsafe cpio path: {name!r}")
    target = (root / Path(*pure.parts)).resolve(strict=False)
    if root.resolve() not in (target, *target.parents):
        raise ValueError(f"cpio path escaped destination: {name!r}")
    return target


def entries(archive: Path):
    with archive.open("rb") as stream:
        while True:
            header = stream.read(HEADER_SIZE)
            if not header:
                return
            if len(header) != HEADER_SIZE or header[:6] not in {b"070701", b"070702"}:
                raise ValueError(f"invalid newc header at offset {stream.tell() - len(header)}")
            fields = [int(header[6 + index * 8:14 + index * 8], 16) for index in range(13)]
            mode, mtime, size, rdevmajor, rdevminor, namesize = (
                fields[1], fields[5], fields[6], fields[9], fields[10], fields[11]
            )
            raw_name = stream.read(namesize)
            if len(raw_name) != namesize or not raw_name.endswith(b"\0"):
                raise ValueError("truncated newc filename")
            name = raw_name[:-1].decode("utf-8", "surrogateescape")
            stream.read(_padding(HEADER_SIZE + namesize))
            data = stream.read(size)
            if len(data) != size:
                raise ValueError(f"truncated newc data for {name}")
            stream.read(_padding(size))
            if name == "TRAILER!!!":
                return
            yield name, mode, mtime, rdevmajor, rdevminor, data


def extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    delayed_directories: list[tuple[Path, int, int]] = []
    for name, mode, mtime, rdevmajor, rdevminor, data in entries(archive):
        target = _safe_target(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            if target.is_symlink() or target.exists():
                if target.is_dir() and not target.is_symlink():
                    pass
                else:
                    target.unlink()
            if stat.S_ISDIR(mode):
                target.mkdir(parents=True, exist_ok=True)
                delayed_directories.append((target, mode, mtime))
                continue
            if stat.S_ISLNK(mode):
                os.symlink(data.decode("utf-8", "surrogateescape"), target)
            elif stat.S_ISREG(mode):
                target.write_bytes(data)
            elif stat.S_ISFIFO(mode):
                os.mkfifo(target, stat.S_IMODE(mode))
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                os.mknod(target, mode, os.makedev(rdevmajor, rdevminor))
            else:
                continue
            if not target.is_symlink():
                os.chmod(target, stat.S_IMODE(mode))
                os.utime(target, (mtime, mtime), follow_symlinks=False)
        except PermissionError:
            # Device nodes are normally supplied by devtmpfs at boot.
            if not (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)):
                raise
    for target, mode, mtime in reversed(delayed_directories):
        os.chmod(target, stat.S_IMODE(mode))
        os.utime(target, (mtime, mtime), follow_symlinks=False)


def _header(name: bytes, mode: int, mtime: int, data_size: int, rdev: int = 0) -> bytes:
    values = (
        1, mode, 0, 0, 1, mtime, data_size,
        0, 0, os.major(rdev) if rdev else 0, os.minor(rdev) if rdev else 0,
        len(name) + 1, 0,
    )
    return b"070701" + b"".join(f"{value & 0xffffffff:08x}".encode("ascii") for value in values)


def _write_entry(stream, root: Path, path: Path, archive_name: str) -> None:
    info = path.lstat()
    name = archive_name.encode("utf-8", "surrogateescape")
    if stat.S_ISLNK(info.st_mode):
        data = os.readlink(path).encode("utf-8", "surrogateescape")
    elif stat.S_ISREG(info.st_mode):
        data = path.read_bytes()
    else:
        data = b""
    stream.write(_header(name, info.st_mode, int(info.st_mtime), len(data), info.st_rdev))
    stream.write(name + b"\0")
    stream.write(b"\0" * _padding(HEADER_SIZE + len(name) + 1))
    stream.write(data)
    stream.write(b"\0" * _padding(len(data)))


def create(source: Path, archive: Path) -> None:
    source = source.resolve()
    paths = sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix())
    with archive.open("wb") as stream:
        for path in paths:
            _write_entry(stream, source, path, path.relative_to(source).as_posix())
        trailer = b"TRAILER!!!"
        stream.write(_header(trailer, 0, 0, 0))
        stream.write(trailer + b"\0")
        stream.write(b"\0" * _padding(HEADER_SIZE + len(trailer) + 1))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    listing = subparsers.add_parser("list")
    listing.add_argument("archive", type=Path)
    extracting = subparsers.add_parser("extract")
    extracting.add_argument("archive", type=Path)
    extracting.add_argument("destination", type=Path)
    creating = subparsers.add_parser("create")
    creating.add_argument("source", type=Path)
    creating.add_argument("archive", type=Path)
    args = parser.parse_args()
    if args.command == "list":
        for name, *_rest in entries(args.archive):
            print(name)
    elif args.command == "extract":
        extract(args.archive, args.destination)
    else:
        create(args.source, args.archive)


if __name__ == "__main__":
    main()
