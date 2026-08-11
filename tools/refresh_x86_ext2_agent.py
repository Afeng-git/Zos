#!/usr/bin/env python3
"""Replace the ZOS shell agent inside the x86 ext2 ramdisk image.

The upstream x86 init.xz expands to an ext2 filesystem rather than a cpio
archive, so it is updated in place without loop-mount privileges.
"""
from __future__ import annotations

import lzma
import re
import struct
import subprocess
import tempfile
from pathlib import Path


class Ext2Image:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.stream = path.open("r+b")
        self.stream.seek(1024)
        superblock = self.stream.read(1024)
        if struct.unpack_from("<H", superblock, 56)[0] != 0xEF53:
            raise ValueError("not an ext2/ext3/ext4 filesystem")
        self.blocks_count = struct.unpack_from("<I", superblock, 4)[0]
        self.first_data_block = struct.unpack_from("<I", superblock, 20)[0]
        self.block_size = 1024 << struct.unpack_from("<I", superblock, 24)[0]
        self.blocks_per_group = struct.unpack_from("<I", superblock, 32)[0]
        self.inodes_per_group = struct.unpack_from("<I", superblock, 40)[0]
        self.inode_size = struct.unpack_from("<H", superblock, 88)[0] or 128
        self.descriptor_size = struct.unpack_from("<H", superblock, 254)[0] or 32
        self.group_table_offset = (2 if self.block_size == 1024 else 1) * self.block_size

    def close(self) -> None:
        self.stream.close()

    def _group_descriptor(self, group: int) -> bytes:
        self.stream.seek(self.group_table_offset + group * self.descriptor_size)
        return self.stream.read(self.descriptor_size)

    def _inode_record(self, inode_number: int) -> tuple[int, bytearray]:
        group = (inode_number - 1) // self.inodes_per_group
        index = (inode_number - 1) % self.inodes_per_group
        descriptor = self._group_descriptor(group)
        inode_table = struct.unpack_from("<I", descriptor, 8)[0]
        offset = inode_table * self.block_size + index * self.inode_size
        self.stream.seek(offset)
        return offset, bytearray(self.stream.read(self.inode_size))

    def _inode(self, inode_number: int) -> dict[str, object]:
        offset, raw = self._inode_record(inode_number)
        return {
            "offset": offset,
            "raw": raw,
            "size": struct.unpack_from("<I", raw, 4)[0],
            "pointers": list(struct.unpack_from("<15I", raw, 40)),
        }

    def _pointer_block(self, block_number: int) -> list[int]:
        self.stream.seek(block_number * self.block_size)
        data = self.stream.read(self.block_size)
        return list(struct.unpack(f"<{self.block_size // 4}I", data))

    def _data_blocks(self, inode: dict[str, object]) -> list[int]:
        size = int(inode["size"])
        required = (size + self.block_size - 1) // self.block_size
        pointers = list(inode["pointers"])
        blocks = [value for value in pointers[:12] if value]
        if len(blocks) < required and pointers[12]:
            blocks.extend(value for value in self._pointer_block(pointers[12]) if value)
        if len(blocks) < required and pointers[13]:
            for indirect in self._pointer_block(pointers[13]):
                if indirect:
                    blocks.extend(value for value in self._pointer_block(indirect) if value)
                if len(blocks) >= required:
                    break
        return blocks[:required]

    def _read_inode(self, inode_number: int) -> bytes:
        inode = self._inode(inode_number)
        data = bytearray()
        for block in self._data_blocks(inode):
            self.stream.seek(block * self.block_size)
            data.extend(self.stream.read(self.block_size))
        return bytes(data[: int(inode["size"])])

    def _list_directory(self, inode_number: int) -> list[tuple[str, int]]:
        data = self._read_inode(inode_number)
        entries: list[tuple[str, int]] = []
        offset = 0
        while offset + 8 <= len(data):
            child, record_length, name_length, _kind = struct.unpack_from("<IHBB", data, offset)
            if record_length < 8:
                break
            name = data[offset + 8 : offset + 8 + name_length].decode("utf-8", "surrogateescape")
            if child:
                entries.append((name, child))
            offset += record_length
        return entries

    def resolve(self, path: str) -> int:
        inode_number = 2
        for component in (part for part in path.split("/") if part):
            for name, child in self._list_directory(inode_number):
                if name == component:
                    inode_number = child
                    break
            else:
                raise FileNotFoundError(path)
        return inode_number

    def replace_file(self, path: str, content: bytes) -> None:
        inode_number = self.resolve(path)
        inode = self._inode(inode_number)
        blocks = self._data_blocks(inode)
        capacity = len(blocks) * self.block_size
        if len(content) > capacity:
            raise ValueError(f"replacement is {len(content)} bytes but inode capacity is {capacity}")
        padded = content + b"\0" * (capacity - len(content))
        for index, block in enumerate(blocks):
            self.stream.seek(block * self.block_size)
            self.stream.write(padded[index * self.block_size : (index + 1) * self.block_size])
        raw = bytearray(inode["raw"])
        struct.pack_into("<I", raw, 4, len(content))
        self.stream.seek(int(inode["offset"]))
        self.stream.write(raw)
        self.stream.flush()


def compact_shell(source: Path) -> bytes:
    """Remove cosmetic indentation outside heredocs without changing payload files."""
    lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    compacted: list[str] = []
    heredoc_end = ""
    heredoc_pattern = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
    for index, line in enumerate(lines):
        if heredoc_end:
            compacted.append(line)
            if line.rstrip("\r\n") == heredoc_end:
                heredoc_end = ""
            continue
        stripped = line.lstrip()
        if index != 0 and (not stripped.strip() or stripped.startswith("#")):
            continue
        compacted.append(line if index == 0 else stripped)
        match = heredoc_pattern.search(line)
        if match:
            heredoc_end = match.group(2)
    return "".join(compacted).encode("utf-8")


def main() -> None:
    project = Path(__file__).resolve().parents[1]
    image = project / "tftp/x86_64/zos/init.xz"
    agent = project / "boot/zos/jingyun-zos-agent"
    with tempfile.TemporaryDirectory(prefix="zos-x86-ext2-") as temporary:
        raw = Path(temporary) / "init.ext2"
        raw.write_bytes(lzma.decompress(image.read_bytes(), format=lzma.FORMAT_XZ))
        filesystem = Ext2Image(raw)
        try:
            filesystem.replace_file("/usr/sbin/jingyun-zos-agent", compact_shell(agent))
        finally:
            filesystem.close()
        rebuilt = Path(temporary) / "init.xz.new"
        with rebuilt.open("wb") as output:
            subprocess.run(["xz", "-1", "-C", "crc32", "-c", str(raw)], stdout=output, check=True)
        subprocess.run(["xz", "-t", str(rebuilt)], check=True)
        rebuilt.replace(image)
    print("x86 ext2 ZOS agent refreshed")


if __name__ == "__main__":
    main()
