// Simplified Chinese UI strings (wide literals, /utf-8 compile).
#pragma once

namespace aps::gui::txt {

constexpr wchar_t kAppTitle[] = L"AppProxySwitch 单应用代理开关";
constexpr wchar_t kEngineGroup[] = L"截流引擎";
constexpr wchar_t kStartEngine[] = L"启动截流";
constexpr wchar_t kStopEngine[] = L"停止截流";
constexpr wchar_t kEngineState[] = L"当前状态：";
constexpr wchar_t kAdminState[] = L"管理员权限：";
constexpr wchar_t kProxyGroup[] = L"Clash / Mihomo 代理设置";
constexpr wchar_t kProxyHost[] = L"代理地址：";
constexpr wchar_t kProxyPort[] = L"代理端口：";
constexpr wchar_t kProxyProtocol[] = L"协议：";
constexpr wchar_t kProxyUser[] = L"用户名（可选）：";
constexpr wchar_t kProxyPass[] = L"密码（可选）：";
constexpr wchar_t kTestProxy[] = L"测试代理";
constexpr wchar_t kRulesGroup[] = L"程序规则（按完整路径匹配，仅 TCP / IPv4）";
constexpr wchar_t kCoverAppDirAlways[] = L"始终覆盖整个应用程序目录";
constexpr wchar_t kAddProgram[] = L"添加程序";
constexpr wchar_t kPickProcess[] = L"从运行进程选择";
constexpr wchar_t kBrowseExe[] = L"浏览 EXE";
constexpr wchar_t kEditRule[] = L"编辑";
constexpr wchar_t kDeleteRule[] = L"删除";
constexpr wchar_t kFlushConns[] = L"中断该规则已有连接";
constexpr wchar_t kClearLog[] = L"清除日志";
constexpr wchar_t kAbout[] = L"关于";
constexpr wchar_t kColEnabled[] = L"启用";
constexpr wchar_t kColName[] = L"程序";
constexpr wchar_t kColPath[] = L"完整路径";
constexpr wchar_t kColPid[] = L"当前 PID";
constexpr wchar_t kColConns[] = L"连接数";
constexpr wchar_t kColTraffic[] = L"已代理流量";
constexpr wchar_t kColError[] = L"最近错误";
constexpr wchar_t kColAction[] = L"操作";
constexpr wchar_t kTrayOpen[] = L"打开主界面";
constexpr wchar_t kTrayEnableAll[] = L"开启全部规则";
constexpr wchar_t kTrayStop[] = L"停止截流";
constexpr wchar_t kTrayExit[] = L"退出";
constexpr wchar_t kStateStopped[] = L"已停止";
constexpr wchar_t kStateStarting[] = L"正在启动";
constexpr wchar_t kStateRunning[] = L"运行中";
constexpr wchar_t kStateDegraded[] = L"运行中（默认端口检测异常）";
constexpr wchar_t kStateDraining[] = L"正在拆除连接";
constexpr wchar_t kStateStopping[] = L"正在停止";
constexpr wchar_t kStateUnknown[] = L"未知";
constexpr wchar_t kYes[] = L"是";
constexpr wchar_t kNo[] = L"否";
constexpr wchar_t kMvpNotice[] =
    L"MVP 仅代理 TCP / IPv4。UDP、QUIC 和部分游戏流量不会被处理（可选开启 UDP "
    L"拦截促使 QUIC 回退 TCP）。本程序不修改系统代理、不依赖 TUN；若你另行开启全局 "
    L"TUN 或系统代理，规则关闭后目标程序仍会被那些全局机制接管。";
constexpr wchar_t kConfirmDelete[] = L"确定删除该规则？";
constexpr wchar_t kConfirmStopEngine[] = L"停止截流引擎？已被代理的连接会被中断。";
constexpr wchar_t kExcludedPath[] =
    L"该程序在环路保护排除名单中（代理核心或本程序自身），不能添加为规则。";
constexpr wchar_t kPickProcessTitle[] = L"从运行进程选择";
constexpr wchar_t kWarnSystemProc[] =
    L"警告：该进程为系统/共享宿主进程，规则会命中大量系统流量，不建议添加。";
constexpr wchar_t kTestOk[] = L"代理可用";
constexpr wchar_t kTestFail[] = L"代理不可用";
constexpr wchar_t kDeleteFailed[] = L"删除失败";
constexpr wchar_t kSaveFailed[] = L"保存失败";
constexpr wchar_t kEngineStartFail[] = L"引擎启动失败（详见日志）";
constexpr wchar_t kEngineDisconnected[] = L"引擎已断开";
constexpr wchar_t kAutostart[] = L"开机启动（仅启动界面，不自动截流）";
constexpr wchar_t kNodeStatus[] = L"节点状态：";
constexpr wchar_t kNodeSwitchNow[] = L"立即测速并切换";
constexpr wchar_t kSubRefresh[] = L"刷新订阅";
constexpr wchar_t kSubRefreshing[] = L"刷新中…";
constexpr wchar_t kSubRefreshOk[] = L"订阅已刷新，节点列表已更新";
constexpr wchar_t kSubRefreshFailed[] = L"订阅刷新失败";
constexpr wchar_t kAutoSwitch[] = L"自动切换";
constexpr wchar_t kDnsCleanSwitch[] = L"代理 DNS";
constexpr wchar_t kManageOutlets[] = L"管理出口";
constexpr wchar_t kApiSecret[] = L"控制器密钥（可选）：";
constexpr wchar_t kWarnSystemDir[] =
    L"该程序位于 Windows 系统目录。覆盖整个目录会把大量系统程序也送入代理，"
    L"可能导致系统功能异常。仍要添加吗？";
// 活动连接 view
constexpr wchar_t kConnectionsGroup[] = L"活动连接（走代理的流量，每秒刷新）：";
constexpr wchar_t kColProc[] = L"进程";
constexpr wchar_t kColTarget[] = L"目标";
constexpr wchar_t kColRule[] = L"规则";
constexpr wchar_t kColOutlet[] = L"出口";
constexpr wchar_t kColDuration[] = L"时长";
constexpr wchar_t kColUp[] = L"上传";
constexpr wchar_t kColDown[] = L"下载";
constexpr wchar_t kColHost[] = L"主机";
constexpr wchar_t kColState[] = L"状态";
constexpr wchar_t kConnStateSyn[] = L"SYN";
constexpr wchar_t kConnStateEstab[] = L"已建立";
constexpr wchar_t kConnStateClosing[] = L"关闭中";
// Rule actions
constexpr wchar_t kColBlocked[] = L"阻止";
constexpr wchar_t kRuleActionLabel[] = L"动作";
constexpr wchar_t kActionProxy[] = L"走代理";
constexpr wchar_t kActionDirect[] = L"强制直连";
constexpr wchar_t kActionBlock[] = L"阻止联网";
// Config export / import
constexpr wchar_t kExportConfig[] = L"导出配置";
constexpr wchar_t kImportConfig[] = L"导入配置";
constexpr wchar_t kConfirmImport[] =
    L"导入将整体覆盖本机规则/出口/代理等设置（本机密码与密钥保留）。继续？";
constexpr wchar_t kExportOk[] = L"配置已导出";
constexpr wchar_t kImportOk[] = L"配置已导入并生效";
constexpr wchar_t kExportFailed[] = L"导出失败";
constexpr wchar_t kImportFailed[] = L"导入失败";
// Region selector
constexpr wchar_t kRegionLabel[] = L"地区：";
constexpr wchar_t kClassLabel[] = L"类型：";
constexpr wchar_t kRegionSwitching[] = L"切换中…（正在测速）";

}  // namespace aps::gui::txt
