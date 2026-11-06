using System;
using System.ServiceProcess;
using LanShareDiag.Models;
using LanShareDiag.Utils;
using Microsoft.Win32;

namespace LanShareDiag.Modules
{
    /// <summary>
    /// P0：lmhosts / ProviderOrder / 来宾登录 / SMB 签名 / SMB1 提示（注册表优先，兼容 Win7）
    /// </summary>
    public static class ClientPolicyModule
    {
        public static void Diagnose(DiagnosisSession session)
        {
            session.Items.Add(CheckLmhosts());
            session.Items.Add(CheckProviderOrder());
            session.Items.Add(CheckInsecureGuest());
            session.Items.Add(CheckSmbSigning());
            session.Items.Add(CheckSmb1OptionalHint());
        }

        private static DiagnosticItem CheckLmhosts()
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "ClientPolicy";
            item.Item = "NetBIOS Helper(lmhosts)";

            try
            {
                using (ServiceController sc = new ServiceController("lmhosts"))
                {
                    int start = ReadDword(@"SYSTEM\CurrentControlSet\Services\lmhosts", "Start", -1);
                    item.CurrentValue = sc.Status + " / Start=" + start;
                    item.Description = "TCP/IP NetBIOS Helper。微软案例：445 可达仍报错误 53 时，常与此服务停止或账户异常有关。";

                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        item.Status = DiagStatus.Ok;
                    }
                    else
                    {
                        item.Status = DiagStatus.Abnormal;
                        item.Recommendation = "将 lmhosts 设为自动并启动。若仍异常，确认其以 Local Service 运行。";
                    }
                }
            }
            catch (Exception ex)
            {
                item.Status = DiagStatus.Error;
                item.Description = "无法查询 lmhosts: " + ex.Message;
            }
            return item;
        }

        private static DiagnosticItem CheckProviderOrder()
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "ClientPolicy";
            item.Item = "网络提供程序顺序";

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"))
                {
                    string order = key != null ? Convert.ToString(key.GetValue("ProviderOrder", "")) : "";
                    item.CurrentValue = order;
                    bool has = !string.IsNullOrEmpty(order)
                        && order.IndexOf("LanmanWorkstation", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (has)
                    {
                        item.Status = DiagStatus.Ok;
                        item.Description = "ProviderOrder 包含 LanmanWorkstation。";
                    }
                    else
                    {
                        item.Status = DiagStatus.Abnormal;
                        item.Description = "ProviderOrder 未包含 LanmanWorkstation。可导致 445 通但仍报错误 53（找不到网络路径）。";
                        item.Recommendation = "在 HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order 的 ProviderOrder 中加入 LanmanWorkstation（需管理员，改前备份）。";
                    }
                }
            }
            catch (Exception ex)
            {
                item.Status = DiagStatus.Error;
                item.Description = ex.Message;
            }
            return item;
        }

        private static DiagnosticItem CheckInsecureGuest()
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "ClientPolicy";
            item.Item = "不安全来宾登录";

            int policy = ReadDword(@"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth", -1);
            int param = ReadDword(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "AllowInsecureGuestAuth", -1);

            // 有效值：策略优先；1=允许，0=禁止；未配置时新版 Win10/11 专业版等默认禁止
            int effective = policy >= 0 ? policy : param;
            bool win10 = OsHelper.IsWindows10OrLater();

            item.CurrentValue = "Policy=" + (policy < 0 ? "未配置" : policy.ToString())
                + "; Parameters=" + (param < 0 ? "未配置" : param.ToString());

            if (effective == 1)
            {
                item.Status = DiagStatus.Ok;
                item.Description = "已允许不安全来宾登录。可访问仅支持 Guest 的 NAS/设备，但有安全风险。";
            }
            else if (effective == 0 || (effective < 0 && win10))
            {
                item.Status = DiagStatus.Warning;
                item.Description = win10 && effective < 0
                    ? "未显式配置；Windows 10 1709+ 专业版/企业版等默认禁止来宾回落。访问无账密 NAS 时常失败（事件 31017）。"
                    : "已禁止不安全来宾登录。目标若只接受 Guest，会提示策略阻止或表现为拒绝访问。";
                item.Recommendation = "优先使用有效用户名密码连接。仅临时排障时可启用 AllowInsecureGuestAuth=1（有安全风险，需确认）。";
            }
            else
            {
                item.Status = DiagStatus.Ok;
                item.Description = "当前系统未强制禁止来宾（常见于 Win7 / 部分家庭版默认）。";
            }

            return item;
        }

        private static DiagnosticItem CheckSmbSigning()
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "ClientPolicy";
            item.Item = "SMB 客户端签名";

            int require = ReadDword(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", -1);
            int enable = ReadDword(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature", -1);

            item.CurrentValue = "Require=" + (require < 0 ? "?" : require.ToString())
                + "; Enable=" + (enable < 0 ? "?" : enable.ToString());

            // Win11 24H2 起默认 Require=1；老 NAS 不支持签名会 Access Denied
            string build = OsHelper.GetBuildNumber();
            int buildNum;
            int.TryParse(build, out buildNum);
            bool likelyWin1124H2 = buildNum >= 26100;

            if (require == 1)
            {
                item.Status = DiagStatus.Warning;
                item.Description = "客户端要求 SMB 签名（RequireSecuritySignature=1）。"
                    + (likelyWin1124H2 ? " 当前系统版本接近 Win11 24H2+ 默认行为。" : "")
                    + " 老旧 NAS/设备若不支持签名会导致连接失败。";
                item.Recommendation = "优先在 NAS/服务器启签名；仅临时排障可关闭客户端“始终数字签名”（有安全风险）。";
            }
            else
            {
                item.Status = DiagStatus.Ok;
                item.Description = "客户端未强制要求签名（或保持默认宽松）。若目标强制签名而协商失败，再看双方策略。";
                if (likelyWin1124H2 && require != 1)
                    item.Description += " 注意：部分版本可能仍由策略覆盖，请结合实际连接错误判断。";
            }

            return item;
        }

        private static DiagnosticItem CheckSmb1OptionalHint()
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "ClientPolicy";
            item.Item = "SMB1 兼容提示";

            int start = ReadDword(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", -1);
            item.CurrentValue = "mrxsmb10 Start=" + (start < 0 ? "无" : start.ToString());

            if (start == 4 || start < 0)
            {
                item.Status = DiagStatus.Warning;
                item.Description = "SMB1 客户端驱动禁用或不存在。仅当目标设备只支持 SMB1 时才会影响访问；现代共享应使用 SMB2/3。";
                item.Recommendation = "不要默认开启 SMB1。仅确认目标为仅 SMB1 老设备时，再手动启用可选功能并评估风险。";
            }
            else
            {
                item.Status = DiagStatus.Ok;
                item.Description = "SMB1 客户端组件未禁用。仍建议优先使用 SMB2/3。";
            }
            return item;
        }

        private static int ReadDword(string subKey, string name, int defaultValue)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey))
                {
                    if (key == null) return defaultValue;
                    object v = key.GetValue(name);
                    if (v == null) return defaultValue;
                    return Convert.ToInt32(v);
                }
            }
            catch
            {
                return defaultValue;
            }
        }
    }
}
