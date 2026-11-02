# LanShareDiag — Windows 局域网共享故障诊断工具

面向运维人员的局域网共享（SMB）分层诊断与安全修复工具。  
兼容 **Windows 7 / 10 / 11**（32/64 位），目标框架 **.NET Framework 4.0**，绿色单文件可运行（需系统已安装 .NET 4.0+）。

## 功能（第一阶段 MVP）

- 本机网络环境检测（多网卡、APIPA、网段匹配、虚拟/VPN 提示）
- Ping / TCP 445 / TCP 139
- Workstation、LanmanServer、mrxsmb10、mrxsmb20 与启动类型
- net use / net view 共享访问与错误码解释（5/53/64/67/86/1219/1326）
- 智能结论（场景 A–G）与可确认的修复操作
- 导出 TXT / HTML / JSON 报告（不含明文密码）

## 编译

要求：已安装 .NET Framework 4.0（或更高，含 MSBuild）。

```bat
build.bat
```

输出：`LanShareDiag\bin\Release\LanShareDiag.exe`

也可用 Visual Studio 2010+ 打开 `LanShareDiag.sln` 编译。

## 运行

双击 `LanShareDiag.exe`。普通权限即可做只读诊断；修复 Workstation / mrxsmb20 / 刷新 DNS 等需管理员，可点界面「以管理员运行」。

## 使用

1. 输入目标 IP 或主机名（可选填写 `\\IP\共享名`）
2. 点「开始诊断」
3. 查看结果列表与结论
4. 按需执行修复（均需确认）
5. 「导出报告」

## 兼容说明

| 能力 | Win7 | Win10+ |
|------|------|--------|
| 注册表/服务/Socket/Ping | 主路径 | 主路径 |
| Get-SmbClientConfiguration | 不使用 | 可选附加信息 |
| SMBClient 事件通道 | 跳过，不判故障 | 尝试读取 |

## 安全原则

先只读诊断，再提示修复；不自动关防火墙、不强开 SMB1、不删全部凭据、不下载替换系统驱动。
