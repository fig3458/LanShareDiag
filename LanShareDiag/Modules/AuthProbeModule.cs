using System;
using System.Net;
using LanShareDiag.Models;
using LanShareDiag.Utils;

namespace LanShareDiag.Modules
{
    /// <summary>
    /// P1：可选凭据探测 IPC$；以及按 IP / 主机名对比访问（不写明文密码到报告）
    /// </summary>
    public static class AuthProbeModule
    {
        public static void Diagnose(DiagnosisSession session)
        {
            string host = session.TargetHost;
            if (string.IsNullOrEmpty(host)) return;

            // 清理可能残留的探测连接（尽力而为，不影响主流程）
            if (!string.IsNullOrEmpty(session.ProbeUserName))
            {
                session.Items.Add(ProbeIpc(host, session.ProbeUserName, session.ProbePassword));
            }
            else
            {
                DiagnosticItem skip = new DiagnosticItem();
                skip.Module = "AuthProbe";
                skip.Item = "IPC$ 凭据探测";
                skip.Status = DiagStatus.NotChecked;
                skip.Description = "未填写探测账号，已跳过。填写用户名后可区分鉴权失败与路径/协议失败。";
                session.Items.Add(skip);
            }

            // 若输入像 IP，尝试再测主机名（反向解析）；若像主机名，再测解析出的 IP
            IPAddress ip;
            bool inputIsIp = IPAddress.TryParse(host, out ip);
            if (inputIsIp)
            {
                string name = TryReverseDns(host);
                DiagnosticItem item = new DiagnosticItem();
                item.Module = "AuthProbe";
                item.Item = "按主机名对比";
                if (string.IsNullOrEmpty(name))
                {
                    item.Status = DiagStatus.Ok;
                    item.CurrentValue = "无PTR";
                    item.Description = "目标以 IP 访问；未解析到主机名。域环境 Kerberos 通常需要名字，工作组/NAS 用 IP+NTLM 更常见。";
                }
                else
                {
                    ProcessResult pr = ProcessHelper.Run("net.exe", "view \\\\" + name, 15000);
                    int err = ShareAccessModule.ExtractSystemError((pr.StdOut ?? "") + (pr.StdErr ?? ""), pr.ExitCode);
                    item.CurrentValue = name + " => err " + err;
                    item.ErrorCode = err;
                    if (pr.ExitCode == 0)
                    {
                        item.Status = DiagStatus.Ok;
                        item.Description = "按主机名 \\\\" + name + " 枚举成功。若仅 IP 失败，可能与 NTLM/Kerberos 或名称解析有关。";
                    }
                    else
                    {
                        item.Status = DiagStatus.Warning;
                        item.Description = "按主机名访问: " + ShareAccessModule.DescribeError(err, (pr.StdOut ?? "") + (pr.StdErr ?? ""));
                        item.Recommendation = ShareAccessModule.RecommendForError(err);
                    }
                }
                session.Items.Add(item);
            }
            else
            {
                if (LocalNetworkModule.TryResolveIPv4(host, out ip))
                {
                    ProcessResult pr = ProcessHelper.Run("net.exe", "view \\\\" + ip, 15000);
                    int err = ShareAccessModule.ExtractSystemError((pr.StdOut ?? "") + (pr.StdErr ?? ""), pr.ExitCode);
                    DiagnosticItem item = new DiagnosticItem();
                    item.Module = "AuthProbe";
                    item.Item = "按IP对比";
                    item.CurrentValue = ip + " => err " + err;
                    item.ErrorCode = err;
                    if (pr.ExitCode == 0)
                    {
                        item.Status = DiagStatus.Ok;
                        item.Description = "按 IP 枚举成功。";
                    }
                    else
                    {
                        item.Status = DiagStatus.Warning;
                        item.Description = "主机名与 IP 结果可能不同。按 IP: " + ShareAccessModule.DescribeError(err, (pr.StdOut ?? "") + (pr.StdErr ?? ""));
                        item.Recommendation = "Win11 若阻止 NTLM，会出现“名字可以、IP 不行”。优先用 FQDN；工作组设备则需放行 NTLM 或配账号。";
                    }
                    session.Items.Add(item);
                }
            }
        }

        private static DiagnosticItem ProbeIpc(string host, string user, string password)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "AuthProbe";
            item.Item = "IPC$ 凭据探测";
            item.CurrentValue = "user=" + user + "（密码已隐藏）";

            // 先删旧连接，避免 1219
            ProcessHelper.Run("net.exe", "use \\\\" + host + "\\IPC$ /delete /y", 8000);

            string args;
            if (string.IsNullOrEmpty(password))
                args = "use \\\\" + host + "\\IPC$ /user:\"" + user + "\" \"\"";
            else
                args = "use \\\\" + host + "\\IPC$ /user:\"" + user + "\" \"" + password.Replace("\"", "\\\"") + "\"";

            ProcessResult pr = ProcessHelper.Run("net.exe", args, 20000);
            string all = ((pr.StdOut ?? "") + "\r\n" + (pr.StdErr ?? "")).Trim();
            int err = ShareAccessModule.ExtractSystemError(all, pr.ExitCode);
            item.ErrorCode = err;

            if (pr.ExitCode == 0)
            {
                item.Status = DiagStatus.Ok;
                item.Description = "使用提供的账号连接 IPC$ 成功。说明网络与鉴权基本可用；若仍进不了某共享，查共享名/共享权限/NTFS。";
            }
            else
            {
                item.Status = DiagStatus.Abnormal;
                item.Description = ShareAccessModule.DescribeError(err, all);
                item.Recommendation = ShareAccessModule.RecommendForError(err);
            }

            // 探测后断开，避免残留
            ProcessHelper.Run("net.exe", "use \\\\" + host + "\\IPC$ /delete /y", 8000);
            return item;
        }

        private static string TryReverseDns(string ip)
        {
            try
            {
                IPHostEntry entry = System.Net.Dns.GetHostEntry(ip);
                if (entry != null && !string.IsNullOrEmpty(entry.HostName))
                    return entry.HostName;
            }
            catch { }
            return string.Empty;
        }
    }
}
