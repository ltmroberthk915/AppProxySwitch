# AppProxySwitch

**1.3.7 界面热修候选：** 修复1.3.6刷新时先重置控件、再布局和滚动造成的整窗闪烁抖动。只批量提交最终位置，跳过无变化的布局和文字；保留实时统计。请使用1.3.7替代1.3.6界面候选。详见[版本说明](docs/RELEASE-1.3.7-REFRESH-JITTER.md)及[验证记录](docs/VALIDATION-1.3.7.md)。

**1.3.6 历史候选（界面回归已由1.3.7替代）：** 后台布局保持顶层窗口可见状态，最小化时跳过连接表重建，重复启动只请求一次打开。控制消息写入增加超时、安全取消及自动重连；转发在背压下更及时响应停止。完整自行弹窗和候选版本的真实模型长流仍需实机验收。详见[候选说明](docs/RELEASE-1.3.6-GUI-VISIBILITY.md)及[验证记录](docs/VALIDATION-1.3.6.md)。

**1.3.5 候选修复：** 新连接在配置热更新时读取同一份出口参数，修正连接线程回收与停止截流的竞争，并同步 socket 关闭与取消操作。包含此前双向转发与服务子组修复；真实模型长流仍需单独验收。详见 [候选说明](docs/RELEASE-1.3.5-RELAY-LIFECYCLE.md)。

Windows 按应用网络路由管理工具。将指定程序的 TCP 连接转发到本地 SOCKS5
出口，支持独立规则、多出口、内核自动发现和活动连接查看。

当前版本：**1.3.2**。

## 下载

在 [1.3.2 发布页](https://github.com/ltmroberthk915/AppProxySwitch/releases/tag/v1.3.2)
下载 Windows x64 安装包或便携包。升级前正常停止引擎并从托盘退出程序。

## 1.3.2 更新

- 增加默认空的 `routing.tls_domain_allowlist`：明确列出的 TLS 域名即使没有
  APS DNS 名称/地址关联，也能按 SOCKS DOMAIN 访问，避免沿用错误的缓存 IP。
- 保留原选中出口、端口、TLS 原字节和半关闭行为；名单外名称继续沿用原规则。
- 提供追加/清空名单的配置命令，通过产品的原子配置保存，保留其他路由、
  节点偏好和加密凭据；命令不会启动引擎。
- 日志记录名称转发或退回 IP 的理由，仅记录连接元数据。

配置步骤与边界：[版本说明](docs/RELEASE-1.3.2-TLS-CACHED-DNS.md)。
验证记录：[1.3.2 验证](docs/VALIDATION-1.3.2.md)。

## 1.3.1 更新

- 规则模式下，优先监测配置 GROUP 偏好所指向、被规则实际引用的服务
  Selector，保留该组作为恢复时的切换目标。
- 节点详情明确当前测速覆盖范围；监测组改变时清除旧延迟和偏好状态。
- Relay 日志记录首先观察到的 EOF 一侧及时间，并区分 TCP 正常结束与
  尚未验证的业务响应完整性，保留双向半关闭行为。
- 只读诊断支持通过 socket 归属识别缺少进程路径的连接；发行包包含
  TCP 控制器、命名管道控制器及共用的路由证据脚本。

详细说明：[版本说明](docs/RELEASE-1.3.1-POLICY-MONITOR.md)。
验证记录：[1.3.1 验证](docs/VALIDATION-1.3.1.md)。

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
