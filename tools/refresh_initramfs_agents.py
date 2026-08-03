#!/usr/bin/env python3
"""Refresh ZOS agents inside the already-verified ARM64/LoongArch64 initramfs."""
from __future__ import annotations

import gzip
import lzma
import shutil
import subprocess
import tempfile
from pathlib import Path

from cpio_newc import create, extract


def executable(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target, follow_symlinks=True)
    target.chmod(0o755)


def refresh_arm(project: Path, workspace: Path) -> None:
    image = project / "tftp/arm64/zos/init.cpio.gz"
    archive = workspace / "arm.cpio"
    archive.write_bytes(gzip.decompress(image.read_bytes()))
    root = workspace / "arm-root"
    extract(archive, root)
    boot = project / "boot/zos"
    executable(boot / "S40network", root / "etc/init.d/S40network")
    executable(boot / "S99zos", root / "etc/init.d/S99fog")
    executable(boot / "jingyun-zos-agent", root / "usr/sbin/jingyun-zos-agent")
    rebuilt = workspace / "arm-zos.cpio"
    create(root, rebuilt)
    with image.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=0) as compressed:
            with rebuilt.open("rb") as source:
                shutil.copyfileobj(source, compressed, 1024 * 1024)


def refresh_loong(project: Path, workspace: Path) -> None:
    image = project / "tftp/loongarch64/zos/initrd.xz"
    archive = workspace / "loong.cpio"
    archive.write_bytes(lzma.decompress(image.read_bytes(), format=lzma.FORMAT_XZ))
    root = workspace / "loong-root"
    extract(archive, root)
    boot = project / "boot/zos"
    executable(
        boot / "jingyun-zos-agent-loongarch64.py",
        root / "usr/sbin/jingyun-zos-agent.py",
    )
    module = root / "usr/lib/zos/zos_multicast.py"
    module.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(project / "zos_multicast.py", module)
    rebuilt = workspace / "loong-zos.cpio"
    create(root, rebuilt)
    temporary_image = workspace / "initrd.xz.new"
    with temporary_image.open("wb") as compressed:
        subprocess.run(
            ["xz", "-1", "-C", "crc32", "-c", str(rebuilt)],
            stdout=compressed,
            check=True,
        )
    subprocess.run(["xz", "-t", str(temporary_image)], check=True)
    # Never leave a half-written boot image behind if compression is interrupted.
    temporary_image.replace(image)


def main() -> None:
    project = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="zos-refresh-initramfs-") as temporary:
        workspace = Path(temporary)
        refresh_arm(project, workspace)
        refresh_loong(project, workspace)
    print("ARM64 and LoongArch64 embedded ZOS agents refreshed")


if __name__ == "__main__":
    main()
