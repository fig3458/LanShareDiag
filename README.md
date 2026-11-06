# LanShareDiag v2 — Windows 局域网共享故障诊断工具

第二版独立目录：`LanShareDiag2`（v1 仍保留在 `LanShareDiag`）。

兼容 **Windows 7 / 10 / 11**，目标 **.NET Framework 4.0**。  
输出为**单个绿色 EXE**（系统已装 .NET 4.0+ 即可运行）。无需 ILMerge/单文件压缩壳——本程序无第三方 DLL，再打包只会增加复杂度且对性能无收益。

## v2 相对 v1 新增

- NetBIOS Helper (`lmhosts`) 检测与一键启动
- 网络提供程序顺序 `ProviderOrder` 是否含 LanmanWorkstation
- 不安全来宾登录策略（AllowInsecureGuestAuth）
- SMB 客户端签名策略（RequireSecuritySignature）
- SMB1 兼容提示（不自动开启）
- 访问目标时的实际本机出口 IP（连 445 观察 LocalEndPoint）
- 可选账号 IPC$ 凭据探测（密码不写报告）
- 主机名 / IP 对比访问
- SMBClient Security 事件（如 31017）提示
- 软件图标

## 编译

```bat
build.bat
```

输出：`LanShareDiag\bin\Release\LanShareDiag.exe`（单文件，可直接拷贝分发）

## 分发建议

只拷贝 `LanShareDiag.exe` 即可。`app.ico` 已嵌入 exe 资源；旁路复制 ico 仅作备用。
