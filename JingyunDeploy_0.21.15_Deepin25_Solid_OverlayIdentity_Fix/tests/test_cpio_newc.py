#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.cpio_newc import create, entries, extract


with tempfile.TemporaryDirectory(prefix="zos-cpio-test-") as temporary:
    root = Path(temporary)
    source = root / "source"
    source.mkdir()
    (source / "etc").mkdir()
    issue = source / "etc/issue"
    issue.write_text("ZOS multiarch\n", encoding="utf-8")
    issue_link = source / "etc/issue-hardlink"
    issue_link.hardlink_to(issue)
    (source / "bin").symlink_to("usr/bin")
    archive = root / "initramfs.cpio"
    create(source, archive)
    names = [entry[0] for entry in entries(archive)]
    assert names == ["bin", "etc", "etc/issue", "etc/issue-hardlink"]
    destination = root / "destination"
    extract(archive, destination)
    extracted_issue = destination / "etc/issue"
    extracted_link = destination / "etc/issue-hardlink"
    assert extracted_issue.read_text(encoding="utf-8") == "ZOS multiarch\n"
    assert extracted_link.read_text(encoding="utf-8") == "ZOS multiarch\n"
    assert extracted_issue.stat().st_ino == extracted_link.stat().st_ino
    assert (destination / "bin").is_symlink()
    assert (destination / "bin").readlink().as_posix() == "usr/bin"

print("dependency-free newc cpio round-trip test passed")
