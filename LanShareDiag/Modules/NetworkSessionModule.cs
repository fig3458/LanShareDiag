using System;
using System.Collections.Generic;
using LanShareDiag.Models;
using LanShareDiag.Utils;

namespace LanShareDiag.Modules
{
    public static class NetworkSessionModule
    {
        public static void Diagnose(DiagnosisSession session, string targetHost)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "Session";
            item.Item = "网络连接(net use)";

            ProcessResult pr = ProcessHelper.Run("net.exe", "use", 10000);
            if (pr.TimedOut)
            {
                item.Status = DiagStatus.Error;
                item.Description = "执行 net use 超时。";
                session.Items.Add(item);
                return;
            }

            string output = (pr.StdOut ?? "") + "\r\n" + (pr.StdErr ?? "");
            List<string> lines = new List<string>();
            string[] raw = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < raw.Length; i++)
            {
                string line = raw[i].Trim();
                if (line.Length == 0) continue;
                // Keep connection-like lines
                if (line.IndexOf("\\\\", StringComparison.Ordinal) >= 0
                    || line.StartsWith("OK", StringComparison.OrdinalIgnoreCase)
                    || line.StartsWith("Unavailable", StringComparison.OrdinalIgnoreCase)
                    || line.IndexOf("断开", StringComparison.Ordinal) >= 0
                    || line.IndexOf("不可用", StringComparison.Ordinal) >= 0)
                {
                    lines.Add(line);
                }
            }

            bool hasConflictHint = false;
            bool hasTarget = false;
            string targetToken = NormalizeHost(targetHost);

            for (int i = 0; i < raw.Length; i++)
            {
                string line = raw[i];
                if (!string.IsNullOrEmpty(targetToken)
                    && line.IndexOf("\\\\" + targetToken, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    hasTarget = true;
                }
                if (line.IndexOf("1219", StringComparison.Ordinal) >= 0)
                    hasConflictHint = true;
            }

            if (lines.Count == 0 && pr.ExitCode == 0)
            {
                item.Status = DiagStatus.Ok;
                item.CurrentValue = "无映射";
                item.Description = "当前没有活动的网络驱动器/连接映射。";
            }
            else
            {
                item.CurrentValue = lines.Count + " 条相关行";
                item.Description = string.Join(" | ", lines.ToArray());
                if (item.Description.Length > 500)
                    item.Description = item.Description.Substring(0, 500) + "...";

                if (hasConflictHint)
                {
                    item.Status = DiagStatus.Abnormal;
                    item.ErrorCode = 1219;
                    item.Recommendation = "同一服务器可能已用其他用户名连接。可清理该目标的 net use 会话后重试。";
                }
                else if (hasTarget)
                {
                    item.Status = DiagStatus.Warning;
                    item.Description += " 已存在指向目标的连接，注意多用户名冲突(错误 1219)。";
                    item.Recommendation = "如遇 1219，先断开目标相关连接再以正确账户连接。";
                }
                else
                {
                    item.Status = DiagStatus.Ok;
                }
            }

            session.Items.Add(item);
            session.AddLog("net use 原始输出摘要长度=" + output.Length);

            // Credential manager: only list target-related names, never passwords
            DiagnosticItem cred = new DiagnosticItem();
            cred.Module = "Session";
            cred.Item = "凭据提示";
            cred.Status = DiagStatus.Ok;
            cred.Description = "不读取明文密码。若出现拒绝访问/1326/86，请检查用户名、密码、共享权限与 NTFS 权限。";
            cred.Recommendation = "在“凭据管理器”中核对目标服务器相关 Windows 凭据；勿让软件自动删除全部凭据。";
            if (!string.IsNullOrEmpty(targetToken))
            {
                ProcessResult cmdkey = ProcessHelper.Run("cmdkey.exe", "/list", 8000);
                string ck = (cmdkey.StdOut ?? "");
                if (ck.IndexOf(targetToken, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    cred.Status = DiagStatus.Warning;
                    cred.CurrentValue = "发现目标相关凭据项";
                    cred.Description += " 凭据列表中出现目标主机名/IP 相关项（仅名称匹配）。";
                }
                else
                {
                    cred.CurrentValue = "未在凭据列表中匹配到目标";
                }
            }
            session.Items.Add(cred);
        }

        private static string NormalizeHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return string.Empty;
            host = host.Trim().Trim('\\');
            int slash = host.IndexOf('\\');
            if (slash >= 0) host = host.Substring(0, slash);
            if (host.StartsWith("\\\\")) host = host.Substring(2);
            return host;
        }
    }
}
