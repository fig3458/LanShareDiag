using System;
using System.Collections.Generic;
using System.Diagnostics;
using LanShareDiag.Models;
using LanShareDiag.Utils;

namespace LanShareDiag.Modules
{
    public static class EventLogModule
    {
        public static void Diagnose(DiagnosisSession session)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "EventLog";
            item.Item = "系统事件摘要";

            List<string> lines = new List<string>();
            int total = 0;

            // System log: Service Control Manager / Tcpip — available on Win7+
            total += AppendRecent("System", new string[] { "Service Control Manager", "Tcpip", "Server", "Workstation" }, lines, 8);

            // SMBClient channel exists mainly on Win8+/Win10 — must not treat missing as fault on Win7
            if (OsHelper.IsWindows10OrLater() || !OsHelper.IsWindows7OrOlder())
            {
                try
                {
                    if (EventLog.Exists("Microsoft-Windows-SMBClient/Operational"))
                    {
                        total += AppendRecent("Microsoft-Windows-SMBClient/Operational", null, lines, 5);
                    }
                    else
                    {
                        lines.Add("SMBClient/Operational 通道不存在（在当前系统上可能不适用）。");
                    }
                }
                catch
                {
                    lines.Add("SMBClient 日志通道不可用（Windows 7 上属正常情况）。");
                }
            }
            else
            {
                lines.Add("当前为 Windows 7 或更早：跳过 SMBClient 专用通道（不存在不视为故障）。");
            }

            item.CurrentValue = total + " 条相关事件";
            item.Description = lines.Count == 0 ? "未取到相关事件。" : string.Join("\r\n", lines.ToArray());
            item.Status = DiagStatus.Ok;
            if (item.Description.IndexOf("失败", StringComparison.Ordinal) >= 0
                || item.Description.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                item.Status = DiagStatus.Warning;
                item.Recommendation = "结合 Workstation/SMB 相关事件进一步排查；完整内容请打开事件查看器。";
            }

            session.Items.Add(item);
        }

        private static int AppendRecent(string logName, string[] sources, List<string> lines, int max)
        {
            int added = 0;
            try
            {
                if (!EventLog.Exists(logName)) return 0;
                using (EventLog log = new EventLog(logName))
                {
                    EventLogEntryCollection entries = log.Entries;
                    int count = entries.Count;
                    DateTime since = DateTime.Now.AddDays(-2);

                    for (int i = count - 1; i >= 0 && added < max; i--)
                    {
                        EventLogEntry e;
                        try { e = entries[i]; }
                        catch { continue; }

                        if (e.TimeGenerated < since) break;
                        if (sources != null && sources.Length > 0)
                        {
                            bool match = false;
                            for (int s = 0; s < sources.Length; s++)
                            {
                                if (string.Equals(e.Source, sources[s], StringComparison.OrdinalIgnoreCase))
                                {
                                    match = true;
                                    break;
                                }
                            }
                            if (!match) continue;
                        }

                        if (e.EntryType != EventLogEntryType.Error && e.EntryType != EventLogEntryType.Warning)
                            continue;

                        string msg = e.Message ?? "";
                        msg = msg.Replace("\r", " ").Replace("\n", " ");
                        if (msg.Length > 120) msg = msg.Substring(0, 120) + "...";
                        lines.Add(string.Format("{0:MM-dd HH:mm} [{1}] {2} ID={3}: {4}",
                            e.TimeGenerated, e.EntryType, e.Source, e.InstanceId, msg));
                        added++;
                    }
                }
            }
            catch (Exception ex)
            {
                lines.Add("读取 " + logName + " 失败: " + ex.Message);
            }
            return added;
        }
    }
}
