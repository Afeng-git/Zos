#!/usr/bin/env python3
"""Build ZOS ARM64 and LoongArch64 test maintenance images from upstream files."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import lzma
import os
import shutil
import tempfile
from pathlib import Path

from cpio_newc import create, extract


ARM_IMAGE_SHA256 = "08057c9868eaea3cefe4d9c2c311af4bbabb9237cbd69ad69d04928437189d65"
ARM_INIT_SHA256 = "716be054f9406c43fc304c7d2b12eaccca599e9d93e24d1b2156f57f00160e70"
LOONG_KERNEL_SHA256 = "60dd7631d5d8f8251c704d60122cb83e3937db50bdc359011de64cb3a0296b9a"
LOONG_INIT_SHA256 = "02d56564efe98d0ee666ef5dc23e6adf92a470da7eab4834ea9b47465c59bdc4"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def verify(path: Path, expected: str) -> None:
    actual = digest(path)
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch for {path}: {actual} != {expected}")


def copy_executable(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target, follow_symlinks=True)
    target.chmod(0o755)


def repair_arm_runtime(root: Path) -> None:
    """Repair FOS command aliases that were hard links in the upstream cpio."""
    repairs = (
        (root / "usr/bin/gawk", "gawk-5.3.2"),
        (root / "bin/gunzip", "gzip"),
    )
    for target, sibling_name in repairs:
        sibling = target.with_name(sibling_name)
        if (
            target.exists() and not target.is_symlink()
            and target.is_file() and target.stat().st_size == 0
            and sibling.is_file() and sibling.stat().st_size > 0
        ):
            target.unlink()
            target.symlink_to(sibling_name)


def build_arm(project: Path, image: Path, init: Path, output: Path, workspace: Path) -> None:
    verify(image, ARM_IMAGE_SHA256)
    verify(init, ARM_INIT_SHA256)
    root = workspace / "arm64-root"
    archive = workspace / "arm64.cpio"
    archive.write_bytes(gzip.decompress(init.read_bytes()))
    extract(archive, root)
    repair_arm_runtime(root)
    boot = project / "boot" / "zos"
    copy_executable(boot / "S40network", root / "etc/init.d/S40network")
    copy_executable(boot / "S99zos", root / "etc/init.d/S99fog")
    copy_executable(boot / "jingyun-zos-agent", root / "usr/sbin/jingyun-zos-agent")
    for name in ("hostname", "hosts", "issue"):
        shutil.copy2(boot / name, root / "etc" / name)
    rebuilt = workspace / "arm64-zos.cpio"
    create(root, rebuilt)
    destination = output / "arm64" / "zos"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(image, destination / "Image")
    with (destination / "init.cpio.gz").open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=0) as compressed:
            with rebuilt.open("rb") as source:
                shutil.copyfileobj(source, compressed, 1024 * 1024)


def build_loong(project: Path, kernel: Path, init: Path, output: Path, workspace: Path) -> None:
    verify(kernel, LOONG_KERNEL_SHA256)
    verify(init, LOONG_INIT_SHA256)
    root = workspace / "loongarch64-root"
    archive = workspace / "loongarch64.cpio"
    archive.write_bytes(lzma.decompress(init.read_bytes(), format=lzma.FORMAT_XZ))
    extract(archive, root)
    boot = project / "boot" / "zos"
    copy_executable(
        boot / "jingyun-zos-agent-loongarch64.py",
        root / "usr/sbin/jingyun-zos-agent.py",
    )
    module_directory = root / "usr/lib/zos"
    module_directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(project / "zos_multicast.py", module_directory / "zos_multicast.py")
    shutil.copy2(
        boot / "zos-loongarch64.service",
        root / "usr/lib/systemd/system/zos-loongarch64.service",
    )
    shutil.copy2(boot / "zos.target", root / "usr/lib/systemd/system/zos.target")
    wants = root / "etc/systemd/system/zos.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    service_link = wants / "zos-loongarch64.service"
    if service_link.exists() or service_link.is_symlink():
        service_link.unlink()
    service_link.symlink_to("/usr/lib/systemd/system/zos-loongarch64.service")
    default_target = root / "etc/systemd/system/default.target"
    if default_target.exists() or default_target.is_symlink():
        default_target.unlink()
    default_target.symlink_to("/usr/lib/systemd/system/zos.target")
    rebuilt = workspace / "loongarch64-zos.cpio"
    create(root, rebuilt)
    destination = output / "loongarch64" / "zos"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(kernel, destination / "vmlinuz")
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 64 * 1024 * 1024}]
    with lzma.open(
        destination / "initrd.xz", "wb", format=lzma.FORMAT_XZ,
        check=lzma.CHECK_CRC32, filters=filters,
    ) as compressed:
        with rebuilt.open("rb") as source:
            shutil.copyfileobj(source, compressed, 1024 * 1024)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--arm-image", type=Path, required=True)
    parser.add_argument("--arm-init", type=Path, required=True)
    parser.add_argument("--loong-kernel", type=Path, required=True)
    parser.add_argument("--loong-init", type=Path, required=True)
    args = parser.parse_args()
    project = args.project.resolve()
    with tempfile.TemporaryDirectory(prefix="zos-multiarch-") as temporary:
        workspace = Path(temporary)
        build_arm(project, args.arm_image, args.arm_init, project / "tftp", workspace)
        build_loong(project, args.loong_kernel, args.loong_init, project / "tftp", workspace)
    print("ARM64 and LoongArch64 ZOS test images built successfully")


if __name__ == "__main__":
    main()
