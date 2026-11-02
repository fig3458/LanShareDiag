using System;
using System.Collections.Generic;

namespace LanShareDiag.Models
{
    public enum DiagStatus
    {
        NotChecked,
        Ok,
        Warning,
        Abnormal,
        NotApplicable,
        Error
    }

    public sealed class DiagnosticItem
    {
        public string Module { get; set; }
        public string Item { get; set; }
        public DiagStatus Status { get; set; }
        public string CurrentValue { get; set; }
        public string ExpectedValue { get; set; }
        public string Description { get; set; }
        public string Recommendation { get; set; }
        public int? ErrorCode { get; set; }
        public long? ElapsedMs { get; set; }
        public DateTime Timestamp { get; set; }

        public DiagnosticItem()
        {
            Timestamp = DateTime.Now;
            Status = DiagStatus.NotChecked;
            CurrentValue = string.Empty;
            ExpectedValue = string.Empty;
            Description = string.Empty;
            Recommendation = string.Empty;
            Module = string.Empty;
            Item = string.Empty;
        }

        public string StatusText
        {
            get
            {
                switch (Status)
                {
                    case DiagStatus.Ok: return "正常";
                    case DiagStatus.Warning: return "警告";
                    case DiagStatus.Abnormal: return "异常";
                    case DiagStatus.NotApplicable: return "不适用";
                    case DiagStatus.Error: return "检测失败";
                    default: return "未检测";
                }
            }
        }
    }

    public sealed class AdapterInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string IPv4 { get; set; }
        public string SubnetMask { get; set; }
        public string Gateway { get; set; }
        public string Dns { get; set; }
        public bool DhcpEnabled { get; set; }
        public string OperationalStatus { get; set; }
        public bool IsVirtualLikely { get; set; }
        public List<string> AllIPv4s { get; set; }

        public AdapterInfo()
        {
            AllIPv4s = new List<string>();
        }

        public bool HasValidUnicastIPv4
        {
            get
            {
                if (AllIPv4s != null)
                {
                    for (int i = 0; i < AllIPv4s.Count; i++)
                    {
                        if (IsValidLanIPv4(AllIPv4s[i])) return true;
                    }
                }
                return IsValidLanIPv4(IPv4);
            }
        }

        public static bool IsValidLanIPv4(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            if (ip.StartsWith("169.254.")) return false;
            if (ip.StartsWith("127.")) return false;
            return true;
        }

        public static bool IsApipa(string ip)
        {
            return !string.IsNullOrEmpty(ip) && ip.StartsWith("169.254.");
        }
    }

    public sealed class LocalHostInfo
    {
        public string ComputerName { get; set; }
        public string OsVersion { get; set; }
        public string OsBuild { get; set; }
        public string Architecture { get; set; }
        public string CurrentUser { get; set; }
        public bool IsAdmin { get; set; }
        public List<AdapterInfo> Adapters { get; set; }

        public LocalHostInfo()
        {
            Adapters = new List<AdapterInfo>();
        }
    }

    public sealed class RepairSuggestion
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public bool RequiresAdmin { get; set; }
        public bool Dangerous { get; set; }
    }

    public sealed class DiagnosisSession
    {
        public string TargetHost { get; set; }
        public string SharePath { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public LocalHostInfo LocalHost { get; set; }
        public List<DiagnosticItem> Items { get; set; }
        public string Conclusion { get; set; }
        public List<string> Recommendations { get; set; }
        public List<RepairSuggestion> RepairSuggestions { get; set; }
        public List<string> Logs { get; set; }

        public DiagnosisSession()
        {
            Items = new List<DiagnosticItem>();
            Recommendations = new List<string>();
            RepairSuggestions = new List<RepairSuggestion>();
            Logs = new List<string>();
            StartedAt = DateTime.Now;
            TargetHost = string.Empty;
            SharePath = string.Empty;
            Conclusion = string.Empty;
        }

        public DiagnosticItem FindItem(string module, string item)
        {
            for (int i = 0; i < Items.Count; i++)
            {
                if (string.Equals(Items[i].Module, module, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Items[i].Item, item, StringComparison.OrdinalIgnoreCase))
                {
                    return Items[i];
                }
            }
            return null;
        }

        public void AddLog(string message)
        {
            Logs.Add(DateTime.Now.ToString("HH:mm:ss.fff") + "  " + message);
        }
    }
}
