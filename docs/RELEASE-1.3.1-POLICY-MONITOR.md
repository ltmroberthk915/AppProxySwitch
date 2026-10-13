# AppProxySwitch 1.3.1

规则模式下，同一内核的多个策略组可以包含相同节点，却各自选择不同出口。
以前 APS 优先监测包含具体节点最多的策略组，`GROUP:` 类型偏好只用于筛选候选。
因此，服务实际走独立策略组时，测速结果和恢复操作可能覆盖通用出口。

现在，选择 `GROUP:<策略组名>` 后，APS 在规则实际引用的选中链中优先监测该
Selector，沿子组解析当前节点，并保留该 Selector 作为切换目标。没有被规则引用
的组仍只作为类型筛选条件；全局模式和旧控制器的选择行为保持原有语义。多个
可用组偏好时按具体成员数量和名称确定单个监测组，不表示同时监测全部业务。
监测组改变时清除旧组的延迟及偏好状态。界面显示测速覆盖的策略组及验证边界。

Relay 日志增加 `tcp_completed`、`application_completion=unverified`、`first_eof`、
`first_eof_ms` 和 `duration_ms`。观察到 EOF 时立即记录来自应用还是代理侧；
半关闭继续允许另一方向传输。TCP 正常关闭仍不能证明 TLS、HTTP 或 WSS 响应完整。
这些字段仅包含连接元数据，不记录请求或响应内容。

发行包包含三个只读诊断脚本。Mihomo 没有提供进程路径时，诊断通过本机
AppProxySwitch 进程持有的连接源地址、源端口和代理端口核对归属。控制器模式、
选中节点与实际业务链分别输出；命名管道诊断仍先核对服务端 PID，所有控制器
请求均为 GET，不切节点、不修改配置、不重启程序。

```powershell
# 服务内核使用命名管道时，传入正在运行的内核 PID。
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\diagnose-kernel-controller.ps1 -CorePid <PID>

# 提供 TCP 控制器的内核，传入实际代理和控制器端口。
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\diagnose-business-route.ps1 -Port <SOCKS端口> -ControllerPort <控制器端口>
```

服务端负载错误、HTTP 5xx 或上游提前关闭，需要依照实际请求日志分别处理。
本版修正监测范围和诊断证据，不能保证所有 Codex 重连都由 APS 消除。无需
迁移 Codex provider 或改写历史会话数据库。升级程序需在通信维护时正常停止
截流、从托盘退出 APS，再运行安装器。
