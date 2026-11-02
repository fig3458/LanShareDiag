using System.Collections.Generic;
using System.Text;
using LanShareDiag.Models;

namespace LanShareDiag.Core
{
    public static class DecisionEngine
    {
        public static void Analyze(DiagnosisSession session)
        {
            DiagnosticItem ping = session.FindItem("IP", "Ping");
            DiagnosticItem tcp445 = session.FindItem("TCP", "TCP 445");
            DiagnosticItem tcp139 = session.FindItem("TCP", "TCP 139");
            DiagnosticItem workstation = session.FindItem("SMBClient", "Workstation");
            DiagnosticItem smb20 = session.FindItem("SMBClient", "SMB 2.0 客户端驱动");
            DiagnosticItem share = session.FindItem("ShareAccess", "共享枚举(net view)");
            DiagnosticItem sessionItem = session.FindItem("Session", "网络连接(net use)");

            bool pingOk = ping != null && ping.Status == DiagStatus.Ok;
            bool pingFail = ping != null && (ping.Status == DiagStatus.Warning || ping.Status == DiagStatus.Abnormal || ping.Status == DiagStatus.Error);
            bool port445Ok = tcp445 != null && tcp445.Status == DiagStatus.Ok;
            bool port445Fail = tcp445 != null && tcp445.Status != DiagStatus.Ok && tcp445.Status != DiagStatus.NotChecked;
            bool wsOk = workstation != null && workstation.Status == DiagStatus.Ok;
            bool smb20Disabled = smb20 != null && smb20.Status == DiagStatus.Abnormal
                && smb20.CurrentValue != null && smb20.CurrentValue.IndexOf("Start=4") >= 0;
            int shareErr = share != null && share.ErrorCode.HasValue ? share.ErrorCode.Value : -1;

            StringBuilder sb = new StringBuilder();
            List<string> recs = new List<string>();
            List<RepairSuggestion> fixes = new List<RepairSuggestion>();

            sb.AppendLine("检测发现：");
            sb.AppendLine();

            // Scenario C/A/B style layered conclusions
            if (pingFail && port445Fail)
            {
                sb.AppendLine("Ping 失败且 TCP 445 无法连接。优先排查网络连通性：目标是否离线、IP 是否错误、VLAN/路由/防火墙/ACL。");
                recs.Add("优先排查二层/三层连通与防火墙，再谈 SMB。");
            }
            else if (pingOk && port445Fail)
            {
                sb.AppendLine("本机可以 Ping 通目标，但 TCP 445 失败。基础 ICMP 可达，SMB 端口不可达。");
                sb.AppendLine("可能原因：目标 SMB 服务未启动、目标防火墙拦截 445、网络 ACL、本机安全软件拦截。");
                recs.Add("在目标机检查文件和打印机共享、LanmanServer、防火墙入站规则。");
                fixes.Add(OpenTool("open_firewall", "打开 Windows 防火墙", false));
            }
            else if (pingFail && port445Ok)
            {
                sb.AppendLine("Ping 失败但 TCP 445 成功。不能判定设备离线；目标很可能禁用了 ICMP。将继续依据 SMB 访问结果判断。");
            }
            else if (pingOk && port445Ok)
            {
                sb.AppendLine("本机可以 Ping 通目标，TCP 445 连接成功，说明基础网络通信及 SMB 端口可达。");
            }

            if (workstation != null)
            {
                if (wsOk)
                    sb.AppendLine("Workstation 服务运行正常。");
                else
                {
                    sb.AppendLine("Workstation 服务异常：" + workstation.CurrentValue + "。访问远程共享依赖该服务。");
                    recs.Add("启动 LanmanWorkstation 并检查依赖服务。");
                    fixes.Add(new RepairSuggestion
                    {
                        Id = "start_workstation",
                        Title = "启动 Workstation 服务",
                        Description = "尝试启动 LanmanWorkstation 服务（需要管理员权限）。",
                        RequiresAdmin = true,
                        Dangerous = false
                    });
                }
            }

            if (smb20Disabled)
            {
                sb.AppendLine();
                sb.AppendLine("发现本机 SMB 2.0 客户端驱动 mrxsmb20 的启动类型为 Disabled，可能导致 SMB 2.x/3.x 协议访问异常。");
                sb.AppendLine("建议将启动类型恢复为 Demand，并启动驱动后重新测试共享访问。");
                recs.Add("修复 mrxsmb20：sc config mrxsmb20 start= demand && sc start mrxsmb20");
                fixes.Add(new RepairSuggestion
                {
                    Id = "fix_mrxsmb20",
                    Title = "修复 SMB 2.0 客户端驱动",
                    Description = "将 mrxsmb20 启动类型设为 Demand 并尝试启动（需管理员确认）。",
                    RequiresAdmin = true,
                    Dangerous = false
                });
            }
            else if (smb20 != null && smb20.Status == DiagStatus.Ok)
            {
                sb.AppendLine("SMB 2.0 客户端驱动配置未见 Disabled 异常。");
            }

            if (share != null)
            {
                sb.AppendLine();
                if (share.Status == DiagStatus.Ok)
                {
                    sb.AppendLine("共享枚举(net view)成功。");
                }
                else
                {
                    sb.AppendLine("共享访问异常：" + (share.Description ?? ""));
                    if (port445Ok && shareErr == 53)
                    {
                        sb.AppendLine("场景判断：445 可达但错误 53 — 重点检查 Workstation、mrxsmb10/20、协议兼容与第三方过滤驱动，不要直接当成权限问题。");
                        recs.Add("核对 SMB 客户端组件与协议协商。");
                    }
                    else if (port445Ok && shareErr == 64)
                    {
                        sb.AppendLine("场景判断：错误 64 — 优先查协议协商、会话中断、Workstation/驱动与安全软件。");
                    }
                    else if (shareErr == 5 || shareErr == 1326 || shareErr == 86)
                    {
                        sb.AppendLine("场景判断：身份验证/权限类错误 — 查凭据、共享权限、NTFS 权限与安全策略。");
                        recs.Add("核对账户与权限，不要修改防火墙作为首要手段。");
                    }
                    else if (shareErr == 1219)
                    {
                        sb.AppendLine("场景判断：会话凭据冲突(1219)。");
                        recs.Add("清理目标相关 net use 连接后，使用单一账户重连。");
                        fixes.Add(new RepairSuggestion
                        {
                            Id = "clear_target_session",
                            Title = "清理目标网络会话",
                            Description = "断开指向目标主机的 net use 连接（需确认，可能影响现有映射）。",
                            RequiresAdmin = false,
                            Dangerous = true
                        });
                    }
                }
            }

            if (sessionItem != null && sessionItem.ErrorCode == 1219)
            {
                fixes.Add(new RepairSuggestion
                {
                    Id = "clear_target_session",
                    Title = "清理目标网络会话",
                    Description = "检测到可能的多用户名连接冲突。",
                    RequiresAdmin = false,
                    Dangerous = true
                });
            }

            // Common safe utilities
            fixes.Add(new RepairSuggestion
            {
                Id = "flush_dns",
                Title = "清理 DNS 缓存",
                Description = "执行 ipconfig /flushdns。",
                RequiresAdmin = true,
                Dangerous = false
            });
            fixes.Add(OpenTool("open_services", "打开服务管理器", false));
            fixes.Add(OpenTool("open_eventvwr", "打开事件查看器", false));
            fixes.Add(OpenTool("open_ncpa", "打开网络适配器", false));

            if (recs.Count == 0)
                recs.Add("若仍无法访问，请导出报告并继续核对目标端共享配置与账户权限。");

            session.Conclusion = sb.ToString().Trim();
            session.Recommendations = Unique(recs);
            session.RepairSuggestions = UniqueFixes(fixes);
        }

        private static RepairSuggestion OpenTool(string id, string title, bool admin)
        {
            return new RepairSuggestion
            {
                Id = id,
                Title = title,
                Description = title,
                RequiresAdmin = admin,
                Dangerous = false
            };
        }

        private static List<string> Unique(List<string> input)
        {
            List<string> list = new List<string>();
            for (int i = 0; i < input.Count; i++)
            {
                if (!list.Contains(input[i])) list.Add(input[i]);
            }
            return list;
        }

        private static List<RepairSuggestion> UniqueFixes(List<RepairSuggestion> input)
        {
            List<RepairSuggestion> list = new List<RepairSuggestion>();
            HashSet<string> ids = new HashSet<string>();
            for (int i = 0; i < input.Count; i++)
            {
                if (ids.Add(input[i].Id)) list.Add(input[i]);
            }
            return list;
        }
    }
}
