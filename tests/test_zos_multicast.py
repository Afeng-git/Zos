#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zos_multicast import receive_stream, send_file


session = "0123456789abcdef-test"
clients = ["02:00:00:00:00:11", "02:00:00:00:00:12"]
outputs = {client: bytearray() for client in clients}
errors: list[Exception] = []
port = 18432


def receiver(client: str) -> None:
    try:
        for block in receive_stream(
            session_id=session, server_ip="127.0.0.1", interface_ip="127.0.0.1",
            data_port=port, client_mac=client, receive_timeout=20,
            _drop_once={(0, 3), (4, 17)} if client == clients[0] else {(2, 9)},
        ):
            outputs[client].extend(block)
    except Exception as error:
        errors.append(error)


with tempfile.TemporaryDirectory(prefix="zos-multicast-test-") as temporary:
    image = Path(temporary) / "test.img.zst"
    payload = os.urandom(2 * 1024 * 1024 + 173)
    image.write_bytes(payload)
    threads = [threading.Thread(target=receiver, args=(client,)) for client in clients]
    for thread in threads:
        thread.start()
    time.sleep(0.25)
    send_file(
        image_path=image, session_id=session, server_ip="127.0.0.1",
        data_port=port, expected_macs=clients, profile="maximum", start_timeout=10,
    )
    for thread in threads:
        thread.join(timeout=10)
    assert not errors, errors
    assert all(not thread.is_alive() for thread in threads)
    assert all(bytes(outputs[client]) == payload for client in clients)

print("ZOS reliable multicast two-receiver retransmission/verification test passed")
