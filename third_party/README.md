# third_party

本目录存放第三方二进制依赖。**仓库不提交任何二进制**，一切通过带校验的脚本获取。

## WinDivert 2.2.2（唯一外部依赖）

- 官方项目：https://github.com/basil00/WinDivert （文档：https://reqrypt.org/windivert-doc.html）
- 官方发布页：https://github.com/basil00/WinDivert/releases （v2.2.2，2022-09-21，当前最新稳定版）
- 许可证：LGPL-3.0 或 GPL-2.0 双许可（随包 `LICENSE` 文件，复制为 `LICENSES/WinDivert-LICENSE.txt`）
- 本项目仅以**未修改的官方文件**形式动态链接分发：`WinDivert.dll`、导入库 `WinDivert.lib`、
  官方签名的内核驱动 `WinDivert64.sys`。不做静态链接，不修改驱动。

## 获取方式

```powershell
powershell -ExecutionPolicy Bypass -File scripts\fetch-windivert.ps1
```

脚本固定以下元数据（升级 WinDivert 必须显式修改脚本并重新核对官方发布页）：

| 项 | 值 |
|---|---|
| 版本 | 2.2.2 |
| 资产 | WinDivert-2.2.2-A.zip（405,137 字节） |
| SHA-256 | `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15` |

布局（脚本自动规范化）：

```
third_party/windivert/
├── include/windivert.h
├── bin/x64/WinDivert.dll
├── bin/x64/WinDivert64.sys
├── lib/x64/WinDivert.lib
└── VERSION.txt
```

`third_party/windivert/` 已被 .gitignore 排除；CMake 在缺失时会报错并提示执行上述脚本。
