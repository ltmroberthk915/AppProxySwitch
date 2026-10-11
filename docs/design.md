# AppProxySwitch 设计文档

本文件记录关键设计决策与理由（对应实施计划的落库版）。

## 1. 总体架构

单 exe 双模式：GUI（manifest `asInvoker`）+ `--engine` 提权引擎进程。
GUI 经 `ShellExecuteEx("runas")` 拉起引擎 → 满足"启用截流才请求管理员权限"
与崩溃隔离。引擎进程退出（含崩溃）→ WinDivert 句柄随进程关闭 → 内核
过滤自然消失 → 全机流量立即恢复原始路径，无需任何清理代码。

## 2. 进程归属（时序竞争三层防线）

| 防线 | 机制 | 覆盖 |
|---|---|---|
| ① | SOCKET 层 CONNECT 事件在 `connect()` 时点（SYN 之前）到达，事件含 PID+五元组，立即 `QueryFullProcessImageName` 并冻结路径 | 常规情况（事件先于 SYN，WFP ALE 处理先于包发送） |
| ② | SYN 未命中映射时**同步**查询 `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`：IPv4 用 AF_INET，IPv6 用 AF_INET6/MIB_TCP6TABLE_OWNER_PID；SYN_SENT 行的属主即真实 PID | 事件延迟/引擎繁忙 |
| ③ | 仍无法解析 → 计数 unresolved、放行直连 | 极端情况，fail-open 方向（漏判=直连，绝不误拦） |

绝不缓存 SYN 等事件（会拖垮全机出站流量）。SOCKET 层端口按官方
socketdump 示例为主机序、地址为 IPv4-mapped IPv6（`::ffff:a.b.c.d`），
提取函数对两种元素序均兼容。

## 3. 整流 NAT（不是"只改 SYN"）

NETWORK 层过滤器（WinDivert 2.2.2 过滤语言**不支持**子网掩码 `127.0.0.0/8`
与地址范围比较——实测确认；只支持精确地址的 `==`/`!=`）：

```
outbound and !impostor and tcp and ip.DstAddr != 127.0.0.1
```

引擎侧在包处理入口再兜底放行整个 127/8 目的（防罕见的 127.x.y.z 本地服务）。

- **整流**：命中 NAT 正向键的该流**每个**出站包都改写目的（SYN 只是建表
  时机）。只改 SYN 会导致后续包直奔真实服务器 → 对方回 RST → 连接必死。
- **重定向目的 = 该连接实际的本机源 IP**：
  真机实测（Win11 26200）注入 dst=127.0.0.1 的包不会被投递给本地监听器
  （无论 IfIdx 如何设置）；而机器到自身 LAN IP 的路径是 Windows 原生环回
  路由，包形状（Loopback=1 + LAN 网卡 IfIdx）与系统自发包完全一致，注入
  可靠。relay 因此绑定 0.0.0.0。1.2.13 起直接使用出站 SYN 已由 Windows
  选定的本机源地址，后续包使用 NAT 项冻结的 `appIp`。不缓存启动网关/IP，
  DHCP/Wi-Fi 变化后新连接立即跟随，多个网卡的连接可同时存在。
- **回程**：relay→应用 的包（src=本机IP:relayPort，outbound 环回标记，
  dst=应用 IP ≠ 127.0.0.1，因此仍被过滤器捕获）把源地址改回原始目的。
  回程识别按 `srcPort == relayPort && (srcIp == dstIp || srcIp == 127.0.0.1)`，
  再核对目的应用的 NAT 反向键；不同连接分别识别各自地址。
- 改包后 `WinDivertHelperCalcChecksums` 重算；注入时保留原始 IfIdx、仅确保
  `Loopback=1`（置 IfIdx=0 会导致注入失败 ERROR_NO_DATA）。`!impostor` 防自环。
- **pass-through 必须重注入**：捕获而未注入 = 丢包 = 断网。引擎对一切
  未处理包原样 send。

SOCKET 层地址布局（实测）：IPv4 存于 element[0]（主机序），element[1] 为
`0x0000FFFF` 标记；端口为主机序（与官方 socketdump 示例一致）。

## 4. 包处理决策表（TCP 句柄所见）

| 包 | 处理 |
|---|---|
| relay(src=127.0.0.1:relayPort)→app，NAT 命中 | 改写 src→origDst，注入 |
| relay→app，NAT miss（杂散连接） | pass-through（relay 侧已直接关闭，不放行成开放代理） |
| app→origDst，NAT 正向命中 | 改写 dst→relay，注入 |
| SYN(新流)，属主命中规则且允许 | 建 NAT、改写、注入 |
| SYN，属主未命中/规则关闭/bypass | pass-through |
| SYN，规则 action=block | 丢弃（黑洞，无 NAT 条目，计数 stats.blocked） |
| SYN，fail-closed 且代理降级 | 丢弃（黑洞） |
| SYN，组播/广播目的（never-proxy） | pass-through（**优先于 block 规则**） |
| 代理规则进程 TCP/53，DNS 防污染开启 | 建 `dnsBridge` NAT，relay 按 TCP DNS 帧本地应答；A 共用干净解析链、AAAA=NODATA；失败/其他 QTYPE 回原解析器 |
| 其他（非规则流的所有包） | pass-through |
| relay→Clash(127.0.0.1:port)、引擎健康检查 | 过滤器天然排除（dst∈127/8），不可见 |
| 引擎注入的包 | 内核侧 `!impostor` 排除 |

UDP（可选第二句柄）：规则进程的对外 UDP（53 除外）丢弃，促成 QUIC 回退
TCP；其余 pass-through。归属仅认已记录的 UDP CONNECT 事件。block 规则同样
丢弃其非 DNS UDP 与 IPv6 SYN（direct 规则两者都放行）——因此 UDP/TCP6
句柄的开门条件 = 全局开关 **或** 存在启用的 block 规则（reload 无法事后
开门，变化记日志提示重启引擎）。DHCP（67/68）与组播/广播在过滤器层排除、
引擎内再兜底直连（fail-open，block 规则也不拦）。

1.2.8 DNS 句柄接收 IPv4/IPv6 UDP 查询与原生响应。只有可确认属于代理规则
的查询默认允许改写（显式兼容配置 `dns_cleanup_global=true` 可恢复全机范围）。
共享系统解析器、未知归属、direct/block 和排除进程立即原样转发；不制造全机
IPv6 REFUSED。代理 A 查询进入 64 项上限的独立队列，排队超过 2 秒回原路径；
AAAA 回 NODATA，两种传输共用当前策略。工作线程应答前再次核对开关与归属。
原生 A/CNAME 回答必须匹配最近查询的端点、接口、ID 和名称，且只接受问题名
的 CNAME 链；这些关联单独缓存，仅用于验证 TLS SNI，不参与干净解析与节点健康。
代理规则 IPv4 TCP/53 的本地 DNS 桥仍保留，关闭时 A/AAAA 均回原解析器。
DNS 句柄常驻，使开关无需重启；退出先唤醒并排空 DNS 工作队列，再关闭捕包句柄。

## 5. NAT 生命周期

正向键 `(appIp,appPort,origDstIp,origDstPort)`；反向键 `(appIp,appPort)`
——TCP 中同一本地 ip:port 不可能同时存在两条活动连接，故反向键可省略
目的二元组，同一对象同时服务回程改写、relay accept 反查、会话强拆。

状态机：`SYN_SENT(30s 无回包→删) → ESTABLISHED(空闲靠 relay keepalive
65s 级检测；绝对上限 24h) → CLOSING(FIN 30s 宽限 / RST 2s 宽限) → 删除`。
同端口重用：create 直接替换旧项。规则决策在 SYN 时点冻结进 NAT 项
（ruleId），RELOAD 不影响存量流。

## 6. teardown RST

NAT 项跟踪 `nextSeqRelayToApp`（每次回程改写时更新 = seq+payload+SYN/FIN）。
强拆时构造 `src=origDst, dst=app, seq=nextSeqRelayToApp` 的 RST+ACK 注入，
应用立即收到"来自原目的"的复位并快速重连（重连时按当前策略直连或再代理）。

## 7. 失败语义

- fail-open（默认）：健康检查（TCP+SOCKS5 greeting，连败 2 次降级/连成
  3 次恢复）→ 降级时新 SYN 直连；10s 后仍降级则对存量 NAT 注 RST 拆链，
  应用自动重连直连。
- fail-closed：降级时丢弃规则进程的新 SYN（拒绝而非直连）。
- relay accept 到未知对端：立即 abortive close（本 relay 永不成为无鉴权
  开放代理）。
- 会话上限：超限后新 SYN 直连 + 状态告警（fail-open 方向）。

## 8. 环路保护

三重：①SOCKET 层归属时按路径/镜像名排除（自身 + clash/mihomo 家族 +
用户自定义）；②NETWORK 过滤器排除 127/8 目的（relay→Clash、健康检查天然
不可见）；③GUI 保存规则时用 `RuleMatcher::isExcludedPath` 拒绝排除名单内
路径。代理地址强制 127/8（校验），防止 Clash 监听公网地址时保护失效。

## 9. 线程与关闭顺序

E1 管道 / E2 SOCKET 泵 / E3 NETWORK 泵（热路径仅两次哈希查找）/ E4 relay
accept / E5x 每会话 / E6 健康 / E7 定时器（1s：NAT 分桶扫描、socket-map
TTL、stats 推送）；G1 GUI / G2 管道读。

锁：socket-map、NAT 用 shared_mutex；RuleSet/Config 用
`atomic<shared_ptr<const T>>` 原子换指针（读侧零锁）；统计 atomic。

STOP 顺序：IPC BYE → 停止新改写 → 注 RST 拆链（注入句柄仍存活）→ 关
NETWORK/SOCKET 句柄（recv 解除阻塞）→ join 包泵 → 关 relay 并 join 会话
（确保 TCP DNS 回调退出）→ 回收 DoH session → join 节点/定时线程 → flush
日志。崩溃路径（无有序关闭）：存量被代理连接超时断开、新连接直连，行为
可预期且已在 README 声明。

## 10. 已知限制与诚实声明

- UDP/QUIC/IPv6/ICMP/域名分流不支持（README 置顶）。
- 不覆盖其他软件的全局 TUN/系统代理；不用 DLL 注入绕过目标程序
  主动读取的系统代理设置。
- SOCKET 事件与 SYN 的跨句柄顺序无内核级保证——由三层防线兜底，且漏判
  方向为直连（安全侧）。
- 全机 outbound TCP 过用户态引擎：重注入包 TTL 会减 1（WinDivert 防环
  行为），对 TTL≥64 的正常流量无实际影响。

## 11. 1.2.0 设计补充（活动连接 / 规则动作 / 关键流量直连 / 地区选择）

- **STATS.connections**：timerPump 每秒推送（仅 STATS，STATUS 不带）。
  内容 = NAT 快照按最近活跃降序、截断 64 条，每项含 proc（PID 反查路径，
  截断 96 字节且不劈 UTF-8）/ 目的 / rule_id / outlet_id / 状态 / 字节 /
  时长 / host（防污染 DNS 缓存线性反查，dns::reverseLookup 纯函数）。
  序列化后数组自身 >40KiB 时逐半裁剪——管道单行 64KiB 上限是唯一静默
  失败点（sendLine 超限返回 false 被丢弃）。仅代理流有 NAT 条目：直连与
  block 流不在列表（block 计数走规则行「阻止」列）。
- **规则三态动作**：RuleMatcher::findEnabledRule 是唯一优先级来源
  （decideTcp / shouldBlockUdp / isEnabledRuleProcess 三处共用）。
  语义矩阵：excluded→Direct；disabled→Direct；never-proxy 目的→Direct
  （先于 block）；block→Block；direct→Direct(带 ruleId)；bypass→Direct；
  否则 Proxy。block 丢弃在引擎 SYN 段（无 NAT 条目、无注入、stats.
  blockedConns++），重复 SYN 每包重判（幂等）。
- **节点状态跨轮携带（回归修复）**：五期重构后定时轮 nodeMonitorRound
  为每出口新建空 NodeStatus，导致 failThreshold>1 的连败计数与地区状态
  每轮清零。现与手动轮一致携带前状态；monitorOneOutlet 入口把
  apiAvailable/apiError 归零、group 拉取成功才置 available，避免携带态
  残留"API 可用"假象。
- **地区选择**：config node_monitor.region（白名单校验）；识别
  region_detect（emoji 国旗对 → IATA → 城市名 → 国家名 → ISO 词元 →
  单字中文，同级冲突保守返回未知）。选择排序键
  `(inRegion 8, withinBudget 4, iepl 2, latency)`；region 为空时退化为
  原两级策略。区内当前节点不被更快区外节点替换；重选后仍不能满足地区
  （服务提供方无该区节点）则置 regionUnavailable 停止逐轮重选，直到地区配置
  变化或手动测速。软偏好 fail-open，README 已声明。
