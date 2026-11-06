# LanShareDiag — Windows 局域网共享故障诊断

诊断「网上邻居 / 共享文件夹 / IPC$」打不开、提示找不到网络路径、凭据失败等常见问题。兼容 **Windows 7 / 10 / 11**，目标 **.NET Framework 4.0**，输出**单个绿色 EXE**。

## 能查什么

- NetBIOS Helper（`lmhosts`）是否在跑，可一键启动
- 网络提供程序顺序 `ProviderOrder` 是否含 LanmanWorkstation
- 不安全来宾登录策略（AllowInsecureGuestAuth）
- SMB 客户端签名策略（RequireSecuritySignature）
- SMB1 兼容提示（不自动开启）
- 访问目标时的本机出口 IP（连 445 观察 LocalEndPoint）
- 可选账号 IPC$ 凭据探测（密码不写报告）
- 主机名 / IP 对比访问
- SMBClient Security 事件（如 31017）提示

## 下载与使用

1. 到 [Releases](https://github.com/fig3458/LanShareDiag/releases) 下载 `LanShareDiag.exe`
2. 建议管理员运行
3. 按界面填写目标主机 / IP，开始诊断；按提示修复或导出报告

## 自行编译

```bat
build.bat
```

产物：`LanShareDiag\bin\Release\LanShareDiag.exe`（可直接拷贝分发）。

## 分发建议

只拷贝 `LanShareDiag.exe` 即可。图标已嵌入 exe。

## 许可证

[MIT](LICENSE)
