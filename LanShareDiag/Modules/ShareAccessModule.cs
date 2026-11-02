using System;
using System.Text.RegularExpressions;
using LanShareDiag.Models;
using LanShareDiag.Utils;

namespace LanShareDiag.Modules
{
    public static class ShareAccessModule
    {
        public static void Diagnose(DiagnosisSession session, string targetHost, string sharePath)
        {
            string uncRoot = BuildUncRoot(targetHost, sharePath);
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "ShareAccess";
            item.Item = "共享枚举(net view)";
            item.CurrentValue = uncRoot;

            if (string.IsNullOrEmpty(uncRoot))
            {
                item.Status = DiagStatus.Error;
                item.Description = "无法构造 UNC 路径。";
                session.Items.Add(item);
                return;
            }

            // net view \\host
            string hostOnly = ExtractHost(uncRoot);
            ProcessResult pr = ProcessHelper.Run("net.exe", "view \\\\" + hostOnly, 20000);
            string all = ((pr.StdOut ?? "") + "\r\n" + (pr.StdErr ?? "")).Trim();

            int err = ExtractSystemError(all, pr.ExitCode);
            item.ErrorCode = err;
            item.ElapsedMs = null;

            if (pr.TimedOut)
            {
                item.Status = DiagStatus.Abnormal;
                item.Description = "net view 超时。";
                item.Recommendation = "检查 Workstation、SMB 驱动、防火墙与目标 SMB 服务。";
            }
            else if (pr.ExitCode == 0)
            {
                item.Status = DiagStatus.Ok;
                item.Description = "成功枚举目标共享。\r\n" + Truncate(all, 400);
            }
            else
            {
                item.Status = DiagStatus.Abnormal;
                item.Description = DescribeError(err, all);
                item.Recommendation = RecommendForError(err);
            }

            session.Items.Add(item);
            session.AddLog("net view \\\\" + hostOnly + " exit=" + pr.ExitCode + " err=" + err);

            // Optional specific share path probe via cmd dir
            string specific = NormalizeSharePath(targetHost, sharePath);
            if (!string.IsNullOrEmpty(specific) && specific.TrimEnd('\\').Split('\\').Length > 3)
            {
                DiagnosticItem pathItem = new DiagnosticItem();
                pathItem.Module = "ShareAccess";
                pathItem.Item = "指定共享路径";
                pathItem.CurrentValue = specific;

                ProcessResult dir = ProcessHelper.Run("cmd.exe", "/c dir \"" + specific + "\"", 20000);
                string dout = ((dir.StdOut ?? "") + "\r\n" + (dir.StdErr ?? "")).Trim();
                int derr = ExtractSystemError(dout, dir.ExitCode);
                pathItem.ErrorCode = derr;

                if (dir.TimedOut)
                {
                    pathItem.Status = DiagStatus.Abnormal;
                    pathItem.Description = "访问指定路径超时。";
                }
                else if (dir.ExitCode == 0)
                {
                    pathItem.Status = DiagStatus.Ok;
                    pathItem.Description = "可以列出目录。\r\n" + Truncate(dout, 300);
                }
                else
                {
                    pathItem.Status = DiagStatus.Abnormal;
                    pathItem.Description = DescribeError(derr, dout);
                    pathItem.Recommendation = RecommendForError(derr);
                }
                session.Items.Add(pathItem);
            }
        }

        private static string BuildUncRoot(string targetHost, string sharePath)
        {
            if (!string.IsNullOrEmpty(sharePath))
            {
                string p = sharePath.Trim();
                if (p.StartsWith("\\\\")) return "\\\\" + ExtractHost(p);
            }
            if (!string.IsNullOrEmpty(targetHost))
                return "\\\\" + targetHost.Trim().Trim('\\');
            return string.Empty;
        }

        private static string NormalizeSharePath(string targetHost, string sharePath)
        {
            if (!string.IsNullOrEmpty(sharePath))
            {
                string p = sharePath.Trim();
                if (p.StartsWith("\\\\")) return p;
                if (!string.IsNullOrEmpty(targetHost))
                    return "\\\\" + targetHost.Trim().Trim('\\') + "\\" + p.Trim('\\');
            }
            return BuildUncRoot(targetHost, sharePath);
        }

        private static string ExtractHost(string unc)
        {
            string s = unc.Trim();
            if (s.StartsWith("\\\\")) s = s.Substring(2);
            int idx = s.IndexOf('\\');
            if (idx >= 0) s = s.Substring(0, idx);
            return s;
        }

        public static int ExtractSystemError(string text, int exitCode)
        {
            if (string.IsNullOrEmpty(text)) return exitCode;

            // English: System error 53 has occurred.
            Match m = Regex.Match(text, @"System error\s+(\d+)", RegexOptions.IgnoreCase);
            if (m.Success) return int.Parse(m.Groups[1].Value);

            // Chinese: 系统错误 53
            m = Regex.Match(text, @"系统错误\s*(\d+)");
            if (m.Success) return int.Parse(m.Groups[1].Value);

            // error 53 / 错误 53
            m = Regex.Match(text, @"(?:error|错误)\s*[:：]?\s*(\d+)", RegexOptions.IgnoreCase);
            if (m.Success) return int.Parse(m.Groups[1].Value);

            return exitCode;
        }

        public static string DescribeError(int code, string raw)
        {
            string meaning;
            switch (code)
            {
                case 5: meaning = "拒绝访问 — 重点查身份验证与权限。"; break;
                case 53: meaning = "找不到网络路径 — 查网络路径、SMB 服务、协议/客户端组件。"; break;
                case 64: meaning = "指定的网络名不再可用 — 查 SMB 会话中断、协议协商、连接异常。"; break;
                case 67: meaning = "找不到网络名 — 共享名称可能错误。"; break;
                case 86: meaning = "指定的网络密码不正确 — 查凭据。"; break;
                case 1219: meaning = "不允许使用多个用户名连接同一服务器 — 会话冲突。"; break;
                case 1326: meaning = "用户名或密码错误 — 身份验证失败。"; break;
                default: meaning = "系统/命令返回错误 " + code + "。"; break;
            }
            string tail = Truncate(raw, 350);
            return meaning + (string.IsNullOrEmpty(tail) ? "" : "\r\n原始输出: " + tail);
        }

        public static string RecommendForError(int code)
        {
            switch (code)
            {
                case 5:
                case 86:
                case 1326:
                    return "检查用户名/密码、目标本地或域账户、共享权限与 NTFS 权限；勿仅凭错误码断定唯一原因。";
                case 53:
                    return "结合 Workstation、mrxsmb10/20、TCP 445 与协议协商综合判断，不要直接当成共享权限问题。";
                case 64:
                    return "检查 SMB 协议协商、Workstation、客户端驱动、目标日志与第三方安全软件。";
                case 67:
                    return "核对共享名称是否正确。";
                case 1219:
                    return "查看现有 net use 连接，清理冲突会话后使用单一账户重连。";
                default:
                    return "结合前序网络/端口/SMB 组件结果综合判断。";
            }
        }

        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            s = s.Replace("\r\n", " ").Replace("\n", " ");
            if (s.Length <= max) return s;
            return s.Substring(0, max) + "...";
        }
    }
}
