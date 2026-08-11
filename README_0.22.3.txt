菁云部署系统 0.22.3（ARM/龙芯管理端组播补全版）

基于 0.22.2 硬件识别与兼容性提示版。

本次只完善管理端组播组件识别/准备：
1. Linux aarch64/ARM64 管理端正式加入 udp-sender 架构识别。
2. Linux LoongArch64/loong64 管理端正式加入 udp-sender 架构识别。
3. 优先使用随包对应架构 udp-sender；不存在时自动使用系统 PATH 中的 udp-sender。
4. 如果仍不存在，在选择组播时可一键自动安装系统 udpcast 包，安装成功后直接继续建立组播任务。
5. 支持 apt-get、dnf、yum、zypper；管理端非 root 时自动尝试 sudo/pkexec。
6. Windows/Linux x86_64 原组播逻辑不变。
7. PXE、单播、硬件采集、Deepin25 个性化、任务逻辑未改。

说明：国产 ARM/龙芯发行版的软件源如果没有 udpcast 包，仍需由发行版提供 native udp-sender，或后续将对应架构的静态二进制放入 tools/udpcast 对应目录。
