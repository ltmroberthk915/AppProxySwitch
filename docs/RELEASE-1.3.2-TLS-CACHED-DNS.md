# 1.3.2：缓存 DNS 地址的显式域名恢复

透明截流时，应用可能沿用启动 APS 前缓存的地址，或者自行解析 DNS。此前 APS
只有在自己的 DNS 缓存中找到名称与原地址的对应关系时，才会用 SOCKS DOMAIN
连接。对应关系缺失时，即使 TLS ClientHello 包含业务域名，也会继续使用原 IP；
如果该地址错误，请求仍会超时。重试同一个缓存地址不能修复这一条件。

新增 `routing.tls_domain_allowlist`，默认空名单。明确列入名单的 TLS 域名无需已有
DNS 关联即可按域名连接。仅影响已经命中代理规则的新连接，沿用原选中出口，
完整保留 TLS 字节和证书验证；名单外的名称继续要求 DNS 关联。不会改变系统
代理、TUN、地区/节点类型偏好，或者结束已有连接。

名单接受完整域名和 `*.domain`，最多 64 项，忽略大小写。通配符包含其下多级
子域，但不包含根域；禁止单独的 `*`、顶级域、IP 和 URL。ECH 使用的覆盖名称
若不在名单中且没有 DNS 关联，仍用原 IP；没有可见 SNI 或识别超时也保持原行为。
按域名连接时，具体目标地址由该出口解析；需要指定固定 IP 的服务应保留在名单外。

升级时取消安装器的“启动 APS”选项，在首次启动界面之前执行下列 PowerShell
命令，为 Codex 通信追加明确的业务域名；完成后再正常启动 APS。已经启动的
界面需先正常退出。命令发现默认配置的界面仍在运行时会拒绝写入，避免稍后
被界面的旧配置副本覆盖。

安装目录的 `scripts/enable-codex-domain-policy.ps1` 也可执行同一配置操作；它先
检查版本，拒绝对旧版 APS 操作，不会启动引擎或停止现有程序。

```powershell
$apsProgram = Join-Path $env:LOCALAPPDATA 'Programs\AppProxySwitch\AppProxySwitch.exe'
& $apsProgram --tls-domain-allow chatgpt.com --tls-domain-allow '*.chatgpt.com' --tls-domain-allow openai.com --tls-domain-allow '*.openai.com'
```

命令通过产品的 `loadConfigFile` / `saveConfigFile` 原子保存，保留现有名单、路由、
节点偏好和加密凭据；相同项不重复追加。它不会启动引擎。可用 `--config <完整
路径>` 指定其他已有配置文件；未知字段、
非法参数和不存在的文件会被拒绝，不制造新配置。清空名单：

```powershell
& $apsProgram --clear-tls-domain-allowlist
```

日志新增 `domain_policy` 与有效 `tls_name`，区分 `configured-name`、`observed-dns`、
`name-not-authorized`、`no-visible-name`、`incomplete-or-timeout` 等情况；仅记录连接
元数据，不记录 TLS 内容、令牌、Cookie。此信息在发起 CONNECT 前也会记录，便于
区分名称恢复缺失和出口连接失败。

该修复解决特定的缓存地址退化路径。上游主动关闭 TLS、Cloudflare 挑战和远端错误
仍需各自核验。匿名 HTTPS / 本地回归成功不能替代关闭应急通道后的实际 Codex
会话验收；升级应先保留应急通信，再按正常方式停止截流、退出 APS 后安装。
