菁云镜像部署系统 0.22.6 — ZOSMC 组播启动握手修复版

本版基于 0.22.5，针对 ARM64 分组组播 4/4 客户端已就绪后长期停留在 state=starting 的问题修复：

1. 修复 ZOSMC 启动死锁
   - 原逻辑：客户端必须等管理端 state=running 后才启动 zosmc-receiver；
     但管理端又必须等接收器 HELLO 握手后才能切换 running，形成互相等待。
   - 新逻辑：当协议为 zosmc1 且状态进入 starting 时，ARM64 客户端立即启动 zosmc-receiver。
   - 接收器 HELLO 后管理端自动切换 running 并开始发送镜像。

2. 等待状态改为单行刷新
   - Multicast group ready: 4/4; state=starting 不再每2秒刷一整行。

3. ZOSMC 握手增加独立超时
   - 全组客户端已 Ready 后，默认 60 秒内必须完成接收器握手。
   - 超时后任务直接进入 failed，并在管理端显示明确失败原因，避免无限 starting。

4. 已重新嵌入 ARM64 init.cpio.gz
   - /usr/sbin/jingyun-zos-agent 已更新到 0.22.6。
   - /usr/sbin/zosmc-receiver 保留并已检查存在。

5. LoongArch64 维护环境同步版本；原来龙芯客户端在 starting 状态即可进入 ZOSMC 接收逻辑，行为保持不变。

6. x86_64 UDPcast 数据链路不做行为修改，避免影响已经稳定的 x86 部署。
