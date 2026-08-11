ZOS Deploy LoongArch64/loong64 manager multicast support.
The manager first uses a bundled udp-sender here when present, then falls back to the system udp-sender.
If neither exists, the GUI can install the distribution udpcast package automatically and retry.
