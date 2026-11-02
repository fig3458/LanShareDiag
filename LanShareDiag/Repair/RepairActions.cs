using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using System.Windows.Forms;
using LanShareDiag.Utils;
using Microsoft.Win32;

namespace LanShareDiag.Repair
{
    public sealed class RepairResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Before { get; set; }
        public string After { get; set; }
        public bool NeedReboot { get; set; }
        public DateTime Time { get; set; }

        public RepairResult()
        {
            Time = DateTime.Now;
            Message = string.Empty;
            Before = string.Empty;
            After = string.Empty;
        }
    }

    public static class RepairActions
    {
        public static RepairResult Execute(string id, string targetHost)
        {
            switch (id)
            {
                case "fix_mrxsmb20":
                    return FixMrxsmb20();
                case "start_workstation":
                    return StartWorkstation();
                case "flush_dns":
                    return FlushDns();
                case "clear_target_session":
                    return ClearTargetSession(targetHost);
                case "open_firewall":
                    return OpenTool("firewall.cpl");
                case "open_services":
                    return OpenTool("services.msc");
                case "open_eventvwr":
                    return OpenTool("eventvwr.msc");
                case "open_ncpa":
                    return OpenTool("ncpa.cpl");
                default:
                    return Fail("未知修复操作: " + id);
            }
        }

        private static RepairResult FixMrxsmb20()
        {
            if (!AdminHelper.IsAdministrator())
                return Fail("需要管理员权限。请以管理员身份重新运行后再执行。");

            RepairResult r = new RepairResult();
            try
            {
                int before = ReadStart("mrxsmb20");
                r.Before = "Start=" + before;

                // Confirm component exists
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\mrxsmb20", true))
                {
                    if (key == null)
                        return Fail("未找到 mrxsmb20 注册表项，拒绝自动修复。请检查系统组件，勿下载替换驱动。");
                }

                ProcessResult cfg = ProcessHelper.Run("sc.exe", "config mrxsmb20 start= demand", 15000);
                ProcessResult start = ProcessHelper.Run("sc.exe", "start mrxsmb20", 15000);

                int after = ReadStart("mrxsmb20");
                r.After = "Start=" + after;
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("sc config 退出码=" + cfg.ExitCode + " " + (cfg.StdOut + cfg.StdErr).Trim());
                sb.AppendLine("sc start 退出码=" + start.ExitCode + " " + (start.StdOut + start.StdErr).Trim());
                sb.AppendLine("修复后 Start=" + after + "（期望 3=Demand）。");

                r.Success = after == 3 || after == 2;
                r.Message = sb.ToString();
                r.NeedReboot = false;
                return r;
            }
            catch (Exception ex)
            {
                return Fail(ex.Message);
            }
        }

        private static RepairResult StartWorkstation()
        {
            if (!AdminHelper.IsAdministrator())
                return Fail("需要管理员权限。");

            RepairResult r = new RepairResult();
            try
            {
                using (ServiceController sc = new ServiceController("LanmanWorkstation"))
                {
                    r.Before = sc.Status.ToString();
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
                    }
                    sc.Refresh();
                    r.After = sc.Status.ToString();
                    r.Success = sc.Status == ServiceControllerStatus.Running;
                    r.Message = r.Success ? "Workstation 已运行。" : "启动后状态=" + r.After;
                }
            }
            catch (Exception ex)
            {
                return Fail(ex.Message);
            }
            return r;
        }

        private static RepairResult FlushDns()
        {
            ProcessResult pr = ProcessHelper.Run("ipconfig.exe", "/flushdns", 15000);
            RepairResult r = new RepairResult();
            r.Success = !pr.TimedOut && pr.ExitCode == 0;
            r.Message = (pr.StdOut + "\r\n" + pr.StdErr).Trim();
            r.Before = "n/a";
            r.After = r.Success ? "flushed" : "failed";
            return r;
        }

        private static RepairResult ClearTargetSession(string targetHost)
        {
            if (string.IsNullOrEmpty(targetHost))
                return Fail("未指定目标主机。");

            string host = targetHost.Trim().Trim('\\');
            int slash = host.IndexOf('\\');
            if (slash >= 0) host = host.Substring(0, slash);

            DialogResult confirm = MessageBox.Show(
                "将执行:\r\nnet use \\\\" + host + "\\* /delete /y\r\n\r\n可能断开与该主机相关的共享连接。是否继续？",
                "确认清理会话",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes)
                return Fail("用户取消。");

            ProcessResult pr = ProcessHelper.Run("net.exe", "use \\\\" + host + "\\* /delete /y", 20000);
            RepairResult r = new RepairResult();
            r.Before = "target=\\\\" + host;
            r.After = "delete requested";
            r.Success = !pr.TimedOut;
            r.Message = (pr.StdOut + "\r\n" + pr.StdErr).Trim();
            return r;
        }

        private static RepairResult OpenTool(string target)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = target,
                    UseShellExecute = true
                });
                RepairResult r = new RepairResult();
                r.Success = true;
                r.Message = "已打开: " + target;
                return r;
            }
            catch (Exception ex)
            {
                return Fail(ex.Message);
            }
        }

        private static int ReadStart(string name)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\" + name))
            {
                if (key == null) return -1;
                object v = key.GetValue("Start");
                return v == null ? -1 : Convert.ToInt32(v);
            }
        }

        private static RepairResult Fail(string msg)
        {
            RepairResult r = new RepairResult();
            r.Success = false;
            r.Message = msg;
            return r;
        }
    }
}
