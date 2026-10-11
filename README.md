# AppProxySwitch

Windows 按应用网络路由管理工具。将指定程序的 TCP 连接转发到本地 SOCKS5
出口，支持独立规则、多出口、内核自动发现和活动连接查看。

当前版本：**1.3.0**。

## 下载

在 [1.3.0 发布页](https://github.com/ltmroberthk915/AppProxySwitch/releases/tag/v1.3.0)
下载 Windows x64 安装包或便携包。升级前正常停止引擎并从托盘退出程序。

## 1.3.0 更新

- 未启动内核只显示名称，同名历史合并；已选或规则绑定的离线出口保留。
- 自动发现缓存不再保存独立的 SOCKS/API 端口字段，当前端口由运行实例
  重新发现。旧缓存首次扫描自动迁移，出口 ID 保持稳定。
- 节点区域增加纵向滚动条，长状态和测试详情自动换行；支持鼠标滚轮、
  滚动条拖动及显示缩放变化后的界面恢复。
- 保留空闲接收心跳、内核模式显示和只读业务路由诊断。

详细说明：[版本说明](docs/RELEASE-1.3.0-KERNEL-HISTORY-SCROLL.md)。
验证记录：[1.3.0 验证](docs/VALIDATION-1.3.0.md)。

## 使用

1. 启动支持 SOCKS5 或 Mixed 端口的本地内核。
2. 启动 AppProxySwitch，选择已发现的内核并点击“测试并连接”；也可以
   手动填写本地出口地址和端口。
3. 添加目标程序，配置并开启规则，点击“启动截流”启动引擎。
4. 在活动连接表查看规则、目标、出口和连接状态。停止引擎后不再转发新连接。

界面以普通权限运行，启动引擎时需要 UAC 确认。规则可选择转发、直连或
阻止新连接，修改规则只影响新连接；已有连接可通过对应按钮中断。

## 功能与边界

- 支持 TCP/IPv4、SOCKS5 认证、完整路径及版本目录通配符、子进程匹配、
  多出口、节点状态、规则与连接表的独立滚动。
- 自动发现 Clash/Mihomo 兼容内核，重新验证运行实例的监听端口和控制器。
  同名多个在线实例各自保留当前端口。
- 不处理 UDP、QUIC、IPv6 或 ICMP 转发。可按规则限制 UDP/IPv6，使支持
  回退的应用使用 TCP/IPv4；相关行为可配置。
- 不修改 Windows 系统代理或第三方 TUN 设置。其他软件启用的全局网络
  配置仍可能影响目标应用。
- 不解密 TLS 或记录应用正文。TLS/DNS 名称关联用于保留已确认的目标
  域名；控制器测速和 SOCKS5 握手不等同于应用业务可达验证。
- 第三方配置更新遵循各客户端自身机制，不自动改变其模式或重启内核。

## 构建与测试

需要 Windows 10/11 x64、Visual Studio 2022 C++ 工具链、CMake 3.24 或更新版本。

```powershell
git clone https://github.com/ltmroberthk915/AppProxySwitch.git
cd AppProxySwitch
powershell -ExecutionPolicy Bypass -File scripts\fetch-windivert.ps1
powershell -ExecutionPolicy Bypass -File build-release.ps1
powershell -ExecutionPolicy Bypass -File scripts\run-tests.ps1 -Config Release
powershell -ExecutionPolicy Bypass -File package-release.ps1
```

安装器另需 Inno Setup 6，运行 `package-installer.ps1` 生成安装包。
发行构建保持 `APS_TEST_HOOKS=OFF`。WinDivert 仅从固定的官方版本获取并
核对 SHA256。技术细节见 [设计文档](docs/design.md)。

## 数据与许可

配置和日志保存在 `%LOCALAPPDATA%\AppProxySwitch\`。配置原子写入，
密码和控制器密钥使用 Windows DPAPI。日志只记录连接元数据。

AppProxySwitch 使用 [MIT 许可](LICENSE)。WinDivert 保留官方未修改文件，
采用其 LGPL/GPL 双许可，详见 [第三方许可](LICENSES/NOTICE.md)。

English: [README.en.md](README.en.md).
