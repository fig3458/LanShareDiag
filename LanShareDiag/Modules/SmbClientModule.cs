using System;
using System.IO;
using System.ServiceProcess;
using LanShareDiag.Models;
using LanShareDiag.Utils;
using Microsoft.Win32;

namespace LanShareDiag.Modules
{
    public static class SmbClientModule
    {
        public static void Diagnose(DiagnosisSession session)
        {
            session.Items.Add(CheckService("LanmanWorkstation", "Workstation", true));
            session.Items.Add(CheckService("LanmanServer", "Server(本机共享)", false));

            session.Items.Add(CheckDriverService("mrxsmb10", "SMB 1.0 客户端驱动", false));
            session.Items.Add(CheckDriverService("mrxsmb20", "SMB 2.0 客户端驱动", true));

            session.Items.Add(CheckProtocolSupport());
        }

        private static DiagnosticItem CheckService(string serviceName, string display, bool criticalForClient)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "SMBClient";
            item.Item = display;

            try
            {
                using (ServiceController sc = new ServiceController(serviceName))
                {
                    string status = sc.Status.ToString();
                    // ServiceController.StartType 仅较新框架提供，Win7/.NET4.0 改读注册表
                    int start = ReadServiceStart(serviceName);
                    string mode = StartTypeText(start);
                    item.CurrentValue = status + " / Start=" + (start < 0 ? "?" : start.ToString()) + "(" + mode + ")";
                    item.Description = "服务 " + serviceName + " 状态=" + status + "，启动类型=" + mode + "。";

                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        item.Status = DiagStatus.Ok;
                    }
                    else if (criticalForClient)
                    {
                        item.Status = DiagStatus.Abnormal;
                        item.Recommendation = "Workstation 负责访问远程共享。请检查依赖服务后启动 LanmanWorkstation。";
                    }
                    else
                    {
                        item.Status = DiagStatus.Warning;
                        item.Description += " 注意：Server 服务影响本机对外共享，不影响本机访问别人。";
                        item.Recommendation = "若只需访问他人共享，Server 停止通常无关；若本机要提供共享再启动。";
                    }
                }
            }
            catch (Exception ex)
            {
                item.Status = DiagStatus.Error;
                item.Description = "无法查询服务 " + serviceName + ": " + ex.Message;
            }

            return item;
        }

        private static DiagnosticItem CheckDriverService(string name, string display, bool smb20Focus)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "SMBClient";
            item.Item = display;

            int start = -1;
            string imagePath = string.Empty;
            bool keyExists = false;

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\" + name))
                {
                    if (key != null)
                    {
                        keyExists = true;
                        object startObj = key.GetValue("Start");
                        if (startObj != null) start = Convert.ToInt32(startObj);
                        object ip = key.GetValue("ImagePath");
                        if (ip != null) imagePath = Environment.ExpandEnvironmentVariables(Convert.ToString(ip)).Trim('"');
                    }
                }
            }
            catch (Exception ex)
            {
                item.Status = DiagStatus.Error;
                item.Description = "读取注册表失败: " + ex.Message;
                return item;
            }

            if (!keyExists)
            {
                item.Status = DiagStatus.Warning;
                item.CurrentValue = "注册表项不存在";
                item.Description = name + " 服务注册表项不存在。在部分精简系统上可能被移除。";
                item.Recommendation = "确认系统组件完整性；不要从网上下载 SYS/DLL 替换。";
                return item;
            }

            string startText = StartTypeText(start);
            item.CurrentValue = "Start=" + start + " (" + startText + ")";
            item.ExpectedValue = smb20Focus ? "3 (Demand) 或 2 (Auto)" : "按系统策略";

            // File existence
            bool fileMissing = false;
            if (!string.IsNullOrEmpty(imagePath))
            {
                string pathCheck = imagePath;
                // ImagePath may be \SystemRoot\System32\drivers\xxx.sys
                if (pathCheck.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
                    pathCheck = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", pathCheck.Substring(12));
                if (pathCheck.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase)
                    || pathCheck.StartsWith(@"System32/", StringComparison.OrdinalIgnoreCase))
                    pathCheck = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", pathCheck);

                if (!File.Exists(pathCheck) && pathCheck.IndexOf(".sys", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    fileMissing = true;
                }
                item.Description = "驱动路径: " + imagePath + (fileMissing ? " （文件缺失）" : "");
            }
            else
            {
                item.Description = "未找到 ImagePath。";
            }

            string svcState = QueryServiceState(name);
            if (!string.IsNullOrEmpty(svcState))
                item.Description += " | 当前状态: " + svcState;

            if (fileMissing)
            {
                item.Status = DiagStatus.Abnormal;
                item.Recommendation = "系统组件可能损坏。请使用系统修复手段，禁止自动下载替换驱动文件。";
                return item;
            }

            if (smb20Focus && start == 4)
            {
                item.Status = DiagStatus.Abnormal;
                item.Description += " SMB 2.0 客户端驱动被禁用，可能导致 SMB 2.x/3.x 访问异常（取决于目标协议协商）。";
                item.Recommendation = "在确认组件存在后，将启动类型恢复为 Demand 并启动驱动，再重测共享。";
                return item;
            }

            // Demand/Auto/System are generally fine; Stopped with Demand is OK
            if (start == 4)
            {
                item.Status = DiagStatus.Warning;
                item.Description += " 驱动已禁用。";
                item.Recommendation = "如需该协议，改为 Demand/Auto。";
            }
            else
            {
                item.Status = DiagStatus.Ok;
                if (smb20Focus)
                    item.Description += " Start=3 按需启动通常正常；不能仅凭 STOPPED 判定故障。";
            }

            return item;
        }

        private static DiagnosticItem CheckProtocolSupport()
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "SMBClient";
            item.Item = "SMB 协议支持";

            bool win7 = OsHelper.IsWindows7OrOlder();
            bool win10 = OsHelper.IsWindows10OrLater();

            int smb10Start = ReadServiceStart("mrxsmb10");
            int smb20Start = ReadServiceStart("mrxsmb20");

            string detail = "系统: " + OsHelper.GetFriendlyOsName() + "。";
            if (win7 || (!win10 && Environment.OSVersion.Version.Major == 6))
            {
                detail += " Windows 7 原生支持 SMB 1.0 与 SMB 2.0/2.1。";
            }
            else
            {
                detail += " Windows 8+/10/11 通常默认 SMB 2.x/3.x；SMB1 多为可选功能。";
            }

            detail += " mrxsmb10 Start=" + (smb10Start < 0 ? "?" : smb10Start.ToString());
            detail += ", mrxsmb20 Start=" + (smb20Start < 0 ? "?" : smb20Start.ToString()) + "。";
            detail += " 仅凭启动类型不能证明实际协商版本。";

            item.Description = detail;
            item.CurrentValue = "SMB1驱动=" + StartTypeText(smb10Start) + "; SMB2驱动=" + StartTypeText(smb20Start);

            if (smb20Start == 4)
            {
                item.Status = DiagStatus.Abnormal;
                item.Recommendation = "恢复 mrxsmb20 为 Demand 后重测。不要把 SMB1 开关当作唯一标准。";
            }
            else
            {
                item.Status = DiagStatus.Ok;
            }

            // Optional Win10+ PowerShell peek — never required for Win7 path
            if (win10)
            {
                try
                {
                    ProcessResult pr = ProcessHelper.Run(
                        "powershell.exe",
                        "-NoProfile -NonInteractive -Command \"try { $c=Get-SmbClientConfiguration -ErrorAction Stop; 'EncryptData='+$c.EncryptData+'; EnableMultiChannel='+$c.EnableMultiChannel } catch { $_.Exception.Message }\"",
                        8000);
                    if (!pr.TimedOut && !string.IsNullOrEmpty(pr.StdOut))
                        item.Description += " | Win10+ SMB客户端配置: " + pr.StdOut.Trim();
                }
                catch { }
            }

            return item;
        }

        private static int ReadServiceStart(string name)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\" + name))
                {
                    if (key == null) return -1;
                    object v = key.GetValue("Start");
                    if (v == null) return -1;
                    return Convert.ToInt32(v);
                }
            }
            catch { return -1; }
        }

        private static string QueryServiceState(string name)
        {
            try
            {
                using (ServiceController sc = new ServiceController(name))
                {
                    return sc.Status.ToString();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string StartTypeText(int start)
        {
            switch (start)
            {
                case 0: return "Boot";
                case 1: return "System";
                case 2: return "Automatic";
                case 3: return "Demand";
                case 4: return "Disabled";
                default: return "Unknown";
            }
        }
    }
}
