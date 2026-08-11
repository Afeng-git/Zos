菁云镜像部署系统 0.22.5 — ARM/龙芯完全离线组播补全版

本版基于 0.22.4，重点修复 ARM64 / LoongArch64 管理端离线组播组件缺失问题：

1. tools/udpcast/linux-aarch64/udp-sender
   - 已包含真实 ARM64 ELF 可执行文件（静态链接）
   - 不依赖 apt/yum，不要求部署管理机访问互联网

2. tools/udpcast/linux-loongarch64/udp-sender
   - 已包含真实 LoongArch64 ELF 可执行文件（静态链接）
   - 不依赖系统 libc，适合银河麒麟/UOS/中科方德等离线管理端

3. ARM64 PXE 可靠组播改为 ZOSMC
   - ARM64 init.cpio.gz 内新增 /usr/sbin/zosmc-receiver
   - 管理端对 ARM64 / LoongArch64 组播统一使用内置 ZOSMC 可靠组播
   - 不再依赖系统安装的 udpcast
   - 支持窗口 ACK/NACK 重传、压缩流 SHA-256 完整性校验

4. LoongArch64
   - 延续原有 ZOSMC Python 接收器，无需外部 udpcast
   - 包内仍提供原生 LoongArch64 udp-sender 工具，便于离线诊断/扩展

5. x86_64
   - 继续保留原有 UDPcast 逻辑，不改变已经稳定的 x86 部署链路

6. 0.22.4 的强制删除/清空异常任务逻辑全部保留。

说明：tools/udpcast/linux-aarch64 和 linux-loongarch64 中的 udp-sender
是菁云 ZOSMC 原生离线发送器，不是 Debian udpcast 包中的二进制；
程序对 ARM64/LoongArch64 正式使用 ZOSMC 协议，因此无需互联网安装组件。
