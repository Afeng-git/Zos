from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "boot/zos/jingyun-zos-agent"


def run_check(command: str) -> subprocess.CompletedProcess[str]:
    script = (
        "set -e\n"
        f'ZOS_AGENT_LIBRARY_ONLY=1 source "{AGENT}"\n'
        f"{command}\n"
    )
    return subprocess.run(["bash", "-c", script], text=True, capture_output=True)


def test_complete_write_accepts_transport_sigpipe() -> None:
    result = run_check("deploy_pipeline_complete 22040360448 22040360448 0 141 0 0")
    assert result.returncode == 0, result.stderr


def test_clean_pipeline_is_successful() -> None:
    result = run_check("deploy_pipeline_complete 22040360448 22040360448 0 0 0 0")
    assert result.returncode == 0, result.stderr


def test_short_write_is_rejected() -> None:
    result = run_check("deploy_pipeline_complete 22040360448 1048576 0 141 0 0")
    assert result.returncode != 0


def test_decoder_failure_is_rejected() -> None:
    result = run_check("deploy_pipeline_complete 22040360448 22040360448 0 141 1 0")
    assert result.returncode != 0


def test_writer_failure_is_rejected() -> None:
    result = run_check("deploy_pipeline_complete 22040360448 22040360448 0 141 0 1")
    assert result.returncode != 0


def test_unexpected_transport_failure_is_rejected() -> None:
    result = run_check("deploy_pipeline_complete 22040360448 22040360448 0 1 0 0")
    assert result.returncode != 0


def test_dd_progress_is_not_connected_to_a_parser_pipe() -> None:
    agent = AGENT.read_text(encoding="utf-8")
    assert '2>"$PROGRESS_STATUS_FILE"' in agent
    assert '2> >(tee /dev/stderr' not in agent
    assert '/bin/busybox awk' in agent


def test_large_progress_value_is_parsed_without_killing_writer(tmp_path) -> None:
    status = tmp_path / "dd.status"
    status.write_text(
        "21474836480 bytes copied\r22150660096 bytes copied\n",
        encoding="utf-8",
    )
    command = (
        f'PROGRESS_STATUS_FILE="{status}"; '
        'value=$(read_dd_status_progress); '
        'test "$value" = 22150660096'
    )
    result = run_check(command)
    assert result.returncode == 0, result.stderr


def test_progress_is_single_line_and_uses_mib() -> None:
    script = (
        "set -e\n"
        f'ZOS_AGENT_LIBRARY_ONLY=1 source "{AGENT}"\n'
        "print_written_progress 111391604736 141733920768\n"
    )
    result = subprocess.run(["bash", "-c", script], capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"MiB" in result.stdout
    assert b"bytes" not in result.stdout
    assert b"\rWritten" in result.stdout
    assert b"\n" not in result.stdout
