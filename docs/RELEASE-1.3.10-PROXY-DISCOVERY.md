# AppProxySwitch 1.3.10

## 代理识别与端口冲突修复

- APS 通过本地监听端口、进程归属和 SOCKS5 握手识别代理。即使程序名称是新出现的，也可以在主窗口选择已验证的 SOCKS5 出口。Clash Neo 会显示启动器及实际提供代理的内核。
- 「自动更换冲突的代理端口」默认开启，可在主窗口关闭。检测到端口被另一进程占用时，APS 会通过已核对归属的 Clash/Mihomo 控制器，为发生冲突的内核分配可用的混合端口或 SOCKS 端口。端口通过归属检查和 SOCKS5 握手后，界面显示原端口和新端口。
- 调整在内核运行期间生效。手动填写旧端口的其他应用需要相应更新。通用 SOCKS5 出口的自动识别与手动选择也适用于没有兼容控制器的代理。

## 验证

Windows 实装验证中，Clash Neo 和另一代理同时配置了端口 `7897`。APS 自动为 Neo 分配了一个空闲端口。原代理和 Neo 各自通过 SOCKS5 握手，原选中的出口继续工作。新端口以本机界面显示为准。

Windows x64 安装包、便携 ZIP 和 SHA-256 校验文件见 [GitHub Release](https://github.com/ltmroberthk915/AppProxySwitch/releases/tag/v1.3.10)。
