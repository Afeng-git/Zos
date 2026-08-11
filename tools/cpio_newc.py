#!/usr/bin/env python3
"""Small dependency-free newc initramfs reader/writer used by ZOS builds.

The reader and writer preserve regular-file hard links.  This matters for FOS:
commands such as ``gawk`` and ``gunzip`` are hard-link aliases in the upstream
initramfs.  Flattening a zero-sized hard-link record into a normal empty file
can make a long disk-writing pipeline fail later with SIGPIPE.
"""
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


def _records(archive: Path):
    with archive.open("rb") as stream:
        while True:
            header = stream.read(HEADER_SIZE)
            if not header:
                return
            if len(header) != HEADER_SIZE or header[:6] not in {b"070701", b"070702"}:
                raise ValueError(f"invalid newc header at offset {stream.tell() - len(header)}")
            fields = [int(header[6 + index * 8:14 + index * 8], 16) for index in range(13)]
            (
                inode, mode, uid, gid, nlink, mtime, size,
                devmajor, devminor, rdevmajor, rdevminor, namesize, checksum,
            ) = fields
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
            yield {
                "name": name,
                "inode": inode,
                "mode": mode,
                "uid": uid,
                "gid": gid,
                "nlink": max(1, nlink),
                "mtime": mtime,
                "devmajor": devmajor,
                "devminor": devminor,
                "rdevmajor": rdevmajor,
                "rdevminor": rdevminor,
                "checksum": checksum,
                "data": data,
            }


def entries(archive: Path):
    """Yield the historical public tuple format used by existing tests/tools."""
    for record in _records(archive):
        yield (
            record["name"], record["mode"], record["mtime"],
            record["rdevmajor"], record["rdevminor"], record["data"],
        )


def _remove_existing(target: Path) -> None:
    if target.is_symlink() or target.exists():
        if target.is_dir() and not target.is_symlink():
            return
        target.unlink()


def _apply_metadata(target: Path, mode: int, mtime: int) -> None:
    if not target.is_symlink():
        os.chmod(target, stat.S_IMODE(mode))
        os.utime(target, (mtime, mtime), follow_symlinks=False)


def extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    delayed_directories: list[tuple[Path, int, int]] = []
    hardlink_sources: dict[tuple[int, int, int], Path] = {}
    pending_hardlinks: dict[tuple[int, int, int], list[tuple[Path, int, int]]] = {}

    for record in _records(archive):
        name = str(record["name"])
        mode = int(record["mode"])
        mtime = int(record["mtime"])
        data = bytes(record["data"])
        target = _safe_target(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            _remove_existing(target)
            if stat.S_ISDIR(mode):
                target.mkdir(parents=True, exist_ok=True)
                delayed_directories.append((target, mode, mtime))
                continue
            if stat.S_ISLNK(mode):
                os.symlink(data.decode("utf-8", "surrogateescape"), target)
                continue
            if stat.S_ISREG(mode) and int(record["nlink"]) > 1:
                key = (
                    int(record["inode"]),
                    int(record["devmajor"]),
                    int(record["devminor"]),
                )
                source = hardlink_sources.get(key)
                if source is not None:
                    os.link(source, target)
                    continue
                if data:
                    target.write_bytes(data)
                    _apply_metadata(target, mode, mtime)
                    hardlink_sources[key] = target
                    for pending, pending_mode, pending_mtime in pending_hardlinks.pop(key, []):
                        _remove_existing(pending)
                        os.link(target, pending)
                        _apply_metadata(pending, pending_mode, pending_mtime)
                else:
                    pending_hardlinks.setdefault(key, []).append((target, mode, mtime))
                continue
            if stat.S_ISREG(mode):
                target.write_bytes(data)
            elif stat.S_ISFIFO(mode):
                os.mkfifo(target, stat.S_IMODE(mode))
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                os.mknod(
                    target,
                    mode,
                    os.makedev(int(record["rdevmajor"]), int(record["rdevminor"])),
                )
            else:
                continue
            _apply_metadata(target, mode, mtime)
        except PermissionError:
            # Device nodes are normally supplied by devtmpfs at boot.
            if not (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)):
                raise

    # A group of genuinely empty hard-linked files has no data-bearing record.
    for members in pending_hardlinks.values():
        if not members:
            continue
        first, first_mode, first_mtime = members[0]
        first.parent.mkdir(parents=True, exist_ok=True)
        _remove_existing(first)
        first.write_bytes(b"")
        _apply_metadata(first, first_mode, first_mtime)
        for target, mode, mtime in members[1:]:
            target.parent.mkdir(parents=True, exist_ok=True)
            _remove_existing(target)
            os.link(first, target)
            _apply_metadata(target, mode, mtime)

    for target, mode, mtime in reversed(delayed_directories):
        os.chmod(target, stat.S_IMODE(mode))
        os.utime(target, (mtime, mtime), follow_symlinks=False)


def _header(
    name: bytes,
    mode: int,
    mtime: int,
    data_size: int,
    rdev: int = 0,
    *,
    inode: int = 1,
    nlink: int = 1,
    devmajor: int = 0,
    devminor: int = 0,
) -> bytes:
    values = (
        inode, mode, 0, 0, max(1, nlink), mtime, data_size,
        devmajor, devminor,
        os.major(rdev) if rdev else 0,
        os.minor(rdev) if rdev else 0,
        len(name) + 1, 0,
    )
    return b"070701" + b"".join(
        f"{value & 0xffffffff:08x}".encode("ascii") for value in values
    )


def _write_entry(
    stream,
    path: Path,
    archive_name: str,
    *,
    inode: int,
    nlink: int,
    include_data: bool,
) -> None:
    info = path.lstat()
    name = archive_name.encode("utf-8", "surrogateescape")
    if stat.S_ISLNK(info.st_mode):
        data = os.readlink(path).encode("utf-8", "surrogateescape")
    elif stat.S_ISREG(info.st_mode) and include_data:
        data = path.read_bytes()
    else:
        data = b""
    stream.write(
        _header(
            name, info.st_mode, int(info.st_mtime), len(data), info.st_rdev,
            inode=inode, nlink=nlink,
        )
    )
    stream.write(name + b"\0")
    stream.write(b"\0" * _padding(HEADER_SIZE + len(name) + 1))
    stream.write(data)
    stream.write(b"\0" * _padding(len(data)))


def create(source: Path, archive: Path) -> None:
    source = source.resolve()
    paths = sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix())

    regular_groups: dict[tuple[int, int], list[Path]] = {}
    for path in paths:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            regular_groups.setdefault((info.st_dev, info.st_ino), []).append(path)

    group_inode: dict[tuple[int, int], int] = {}
    next_inode = 1
    with archive.open("wb") as stream:
        for path in paths:
            info = path.lstat()
            group_key = (info.st_dev, info.st_ino)
            group = regular_groups.get(group_key, [])
            if group:
                inode = group_inode.get(group_key)
                if inode is None:
                    inode = next_inode
                    next_inode += 1
                    group_inode[group_key] = inode
                nlink = len(group)
                # newc convention stores content on exactly one member.
                include_data = path == group[-1]
            else:
                inode = next_inode
                next_inode += 1
                nlink = 1
                include_data = True
            _write_entry(
                stream,
                path,
                path.relative_to(source).as_posix(),
                inode=inode,
                nlink=nlink,
                include_data=include_data,
            )
        trailer = b"TRAILER!!!"
        stream.write(_header(trailer, 0, 0, 0, inode=next_inode))
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
