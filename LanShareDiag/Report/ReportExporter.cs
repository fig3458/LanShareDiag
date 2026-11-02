using System;
using System.IO;
using System.Text;
using LanShareDiag.Models;

namespace LanShareDiag.Report
{
    public static class ReportExporter
    {
        public static void ExportTxt(DiagnosisSession session, string path)
        {
            File.WriteAllText(path, BuildText(session), Encoding.UTF8);
        }

        public static void ExportHtml(DiagnosisSession session, string path)
        {
            File.WriteAllText(path, BuildHtml(session), Encoding.UTF8);
        }

        public static void ExportJson(DiagnosisSession session, string path)
        {
            // Minimal JSON without external dependency (.NET 4.0)
            File.WriteAllText(path, BuildJson(session), Encoding.UTF8);
        }

        public static string BuildText(DiagnosisSession session)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Windows 局域网共享故障诊断报告");
            sb.AppendLine("================================");
            sb.AppendLine("生成时间: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("目标主机: " + session.TargetHost);
            sb.AppendLine("共享路径: " + session.SharePath);
            sb.AppendLine("开始: " + session.StartedAt.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("结束: " + session.FinishedAt.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine();

            if (session.LocalHost != null)
            {
                sb.AppendLine("[计算机基本信息]");
                sb.AppendLine("计算机名: " + session.LocalHost.ComputerName);
                sb.AppendLine("系统版本: " + session.LocalHost.OsVersion);
                sb.AppendLine("架构: " + session.LocalHost.Architecture);
                sb.AppendLine("当前账户: " + session.LocalHost.CurrentUser);
                sb.AppendLine("管理员: " + (session.LocalHost.IsAdmin ? "是" : "否"));
                sb.AppendLine();
                sb.AppendLine("[本机网络配置]");
                for (int i = 0; i < session.LocalHost.Adapters.Count; i++)
                {
                    AdapterInfo a = session.LocalHost.Adapters[i];
                    sb.AppendLine(string.Format("- {0} | {1} | {2}/{3} | GW={4} | DNS={5} | DHCP={6} | {7}{8}",
                        a.Name, a.OperationalStatus, a.IPv4, a.SubnetMask, a.Gateway, a.Dns,
                        a.DhcpEnabled, a.Description, a.IsVirtualLikely ? " [虚拟/VPN可能]" : ""));
                }
                sb.AppendLine();
            }

            sb.AppendLine("[检测结果]");
            for (int i = 0; i < session.Items.Count; i++)
            {
                DiagnosticItem it = session.Items[i];
                sb.AppendLine(string.Format("{0}. [{1}] {2} = {3}", i + 1, it.Module, it.Item, it.StatusText));
                if (!string.IsNullOrEmpty(it.CurrentValue)) sb.AppendLine("   当前值: " + it.CurrentValue);
                if (!string.IsNullOrEmpty(it.Description)) sb.AppendLine("   详情: " + it.Description.Replace("\r\n", " | "));
                if (!string.IsNullOrEmpty(it.Recommendation)) sb.AppendLine("   建议: " + it.Recommendation);
                if (it.ErrorCode.HasValue) sb.AppendLine("   错误码: " + it.ErrorCode.Value);
                if (it.ElapsedMs.HasValue) sb.AppendLine("   耗时ms: " + it.ElapsedMs.Value);
            }
            sb.AppendLine();

            sb.AppendLine("[智能诊断结论]");
            sb.AppendLine(session.Conclusion);
            sb.AppendLine();
            sb.AppendLine("[推荐修复步骤]");
            for (int i = 0; i < session.Recommendations.Count; i++)
                sb.AppendLine((i + 1) + ". " + session.Recommendations[i]);
            sb.AppendLine();
            sb.AppendLine("[可用修复操作]");
            for (int i = 0; i < session.RepairSuggestions.Count; i++)
            {
                RepairSuggestion f = session.RepairSuggestions[i];
                sb.AppendLine("- " + f.Title + (f.RequiresAdmin ? " [需管理员]" : "") + (f.Dangerous ? " [需确认]" : ""));
            }
            sb.AppendLine();
            sb.AppendLine("[过程日志]");
            for (int i = 0; i < session.Logs.Count; i++)
                sb.AppendLine(session.Logs[i]);
            sb.AppendLine();
            sb.AppendLine("注: 报告不含明文密码。");
            return sb.ToString();
        }

        private static string BuildHtml(DiagnosisSession session)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset=\"utf-8\"/><title>诊断报告</title>");
            sb.AppendLine("<style>body{font-family:Segoe UI,Microsoft YaHei,sans-serif;margin:24px;color:#222}");
            sb.AppendLine("table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}");
            sb.AppendLine("th{background:#f3f3f3}.ok{color:#0a7a2f}.bad{color:#b00020}.warn{color:#9a6b00}pre{background:#f7f7f7;padding:12px;white-space:pre-wrap}</style></head><body>");
            sb.AppendLine("<h1>Windows 局域网共享故障诊断报告</h1>");
            sb.AppendLine("<p>生成时间: " + Html(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")) + "<br/>");
            sb.AppendLine("目标: " + Html(session.TargetHost) + " &nbsp; 路径: " + Html(session.SharePath) + "</p>");

            if (session.LocalHost != null)
            {
                sb.AppendLine("<h2>本机信息</h2><ul>");
                sb.AppendLine("<li>计算机: " + Html(session.LocalHost.ComputerName) + "</li>");
                sb.AppendLine("<li>系统: " + Html(session.LocalHost.OsVersion) + "</li>");
                sb.AppendLine("<li>账户: " + Html(session.LocalHost.CurrentUser) + "（管理员: " + (session.LocalHost.IsAdmin ? "是" : "否") + "）</li>");
                sb.AppendLine("</ul>");
            }

            sb.AppendLine("<h2>检测结果</h2><table><tr><th>模块</th><th>项目</th><th>状态</th><th>详情</th></tr>");
            for (int i = 0; i < session.Items.Count; i++)
            {
                DiagnosticItem it = session.Items[i];
                string cls = it.Status == DiagStatus.Ok ? "ok" : (it.Status == DiagStatus.Warning ? "warn" : (it.Status == DiagStatus.Abnormal || it.Status == DiagStatus.Error ? "bad" : ""));
                sb.AppendLine("<tr><td>" + Html(it.Module) + "</td><td>" + Html(it.Item) + "</td><td class=\"" + cls + "\">"
                    + Html(it.StatusText) + "</td><td>" + Html(it.Description) + "</td></tr>");
            }
            sb.AppendLine("</table>");
            sb.AppendLine("<h2>诊断结论</h2><pre>" + Html(session.Conclusion) + "</pre>");
            sb.AppendLine("<h2>建议</h2><ol>");
            for (int i = 0; i < session.Recommendations.Count; i++)
                sb.AppendLine("<li>" + Html(session.Recommendations[i]) + "</li>");
            sb.AppendLine("</ol>");
            sb.AppendLine("<p><em>报告不含明文密码。</em></p></body></html>");
            return sb.ToString();
        }

        private static string BuildJson(DiagnosisSession session)
        {
            // Use XElement-like manual escaping for simplicity
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            sb.Append("\"targetHost\":").Append(J(session.TargetHost)).Append(",");
            sb.Append("\"sharePath\":").Append(J(session.SharePath)).Append(",");
            sb.Append("\"startedAt\":").Append(J(session.StartedAt.ToString("o"))).Append(",");
            sb.Append("\"finishedAt\":").Append(J(session.FinishedAt.ToString("o"))).Append(",");
            sb.Append("\"conclusion\":").Append(J(session.Conclusion)).Append(",");
            sb.Append("\"items\":[");
            for (int i = 0; i < session.Items.Count; i++)
            {
                DiagnosticItem it = session.Items[i];
                if (i > 0) sb.Append(",");
                sb.Append("{");
                sb.Append("\"module\":").Append(J(it.Module)).Append(",");
                sb.Append("\"item\":").Append(J(it.Item)).Append(",");
                sb.Append("\"status\":").Append(J(it.Status.ToString())).Append(",");
                sb.Append("\"currentValue\":").Append(J(it.CurrentValue)).Append(",");
                sb.Append("\"expectedValue\":").Append(J(it.ExpectedValue)).Append(",");
                sb.Append("\"description\":").Append(J(it.Description)).Append(",");
                sb.Append("\"recommendation\":").Append(J(it.Recommendation));
                if (it.ErrorCode.HasValue) sb.Append(",\"errorCode\":").Append(it.ErrorCode.Value);
                sb.Append("}");
            }
            sb.Append("],\"recommendations\":[");
            for (int i = 0; i < session.Recommendations.Count; i++)
            {
                if (i > 0) sb.Append(",");
                sb.Append(J(session.Recommendations[i]));
            }
            sb.Append("]}");
            return sb.ToString();
        }

        private static string Html(string s)
        {
            if (s == null) return "";
            return System.Security.SecurityElement.Escape(s) ?? "";
        }

        private static string J(string s)
        {
            if (s == null) s = "";
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32) sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }
    }
}
