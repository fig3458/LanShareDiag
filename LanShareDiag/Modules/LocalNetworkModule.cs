using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using LanShareDiag.Models;
using LanShareDiag.Utils;

namespace LanShareDiag.Modules
{
    public static class LocalNetworkModule
    {
        public static LocalHostInfo CollectLocalHost()
        {
            LocalHostInfo info = new LocalHostInfo();
            info.ComputerName = Environment.MachineName;
            info.OsVersion = OsHelper.GetFriendlyOsName();
            info.OsBuild = OsHelper.GetBuildNumber();
            info.Architecture = OsHelper.GetArchitecture();
            info.CurrentUser = Environment.UserDomainName + "\\" + Environment.UserName;
            info.IsAdmin = AdminHelper.IsAdministrator();
            info.Adapters = CollectAdapters();
            return info;
        }

        public static List<DiagnosticItem> Diagnose(LocalHostInfo host, string targetHost)
        {
            List<DiagnosticItem> items = new List<DiagnosticItem>();

            DiagnosticItem summary = new DiagnosticItem();
            summary.Module = "LocalNetwork";
            summary.Item = "本机网络";
            summary.Status = DiagStatus.Ok;
            summary.Description = "计算机: " + host.ComputerName
                + " | OS: " + host.OsVersion
                + " | 账户: " + host.CurrentUser
                + " | 管理员: " + (host.IsAdmin ? "是" : "否");

            int upCount = 0;
            int upWithValidIp = 0;
            int gatewayCount = 0;
            HashSet<string> gateways = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<string> validIps = new List<string>();
            List<string> apipaOnUp = new List<string>();
            List<string> apipaOnDownOrVirtual = new List<string>();

            for (int i = 0; i < host.Adapters.Count; i++)
            {
                AdapterInfo a = host.Adapters[i];
                bool isUp = string.Equals(a.OperationalStatus, "Up", StringComparison.OrdinalIgnoreCase);
                if (isUp) upCount++;
                if (isUp && a.HasValidUnicastIPv4) upWithValidIp++;

                List<string> ips = a.AllIPv4s != null && a.AllIPv4s.Count > 0
                    ? a.AllIPv4s
                    : (!string.IsNullOrEmpty(a.IPv4) ? new List<string> { a.IPv4 } : new List<string>());

                for (int j = 0; j < ips.Count; j++)
                {
                    string ip = ips[j];
                    if (AdapterInfo.IsValidLanIPv4(ip) && !validIps.Contains(ip))
                        validIps.Add(ip);
                    if (AdapterInfo.IsApipa(ip))
                    {
                        string tag = a.Name + "(" + ip + ")";
                        if (isUp && !a.IsVirtualLikely && !a.HasValidUnicastIPv4)
                            apipaOnUp.Add(tag);
                        else
                            apipaOnDownOrVirtual.Add(tag);
                    }
                }

                if (isUp && !string.IsNullOrEmpty(a.Gateway))
                {
                    string[] parts = a.Gateway.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    for (int g = 0; g < parts.Length; g++)
                    {
                        string gwIp = parts[g].Trim();
                        if (gwIp.Length > 0) gateways.Add(gwIp);
                    }
                }
            }
            gatewayCount = gateways.Count;

            summary.CurrentValue = "活动网卡 " + upCount + " 个, 有效IPv4 " + validIps.Count + " 个"
                + (validIps.Count > 0 ? " [" + string.Join(", ", validIps.ToArray()) + "]" : "");
            if (validIps.Count > 0)
            {
                summary.Status = DiagStatus.Ok;
                summary.Description += " | 主通信地址看起来正常。";
            }
            items.Add(summary);

            // 多网卡：系统里有很多虚拟网卡很常见，只对“多个已连接且带有效 IP 的出口”告警
            if (upWithValidIp > 1)
            {
                DiagnosticItem multi = new DiagnosticItem();
                multi.Module = "LocalNetwork";
                multi.Item = "多网卡";
                multi.Status = DiagStatus.Warning;
                multi.CurrentValue = "有效出口 " + upWithValidIp + " / 适配器总数 " + host.Adapters.Count;
                multi.Description = "有多个已连接且带有效 IP 的适配器，访问目标时可能走错出口（VPN/虚拟网卡）。";
                multi.Recommendation = "确认访问局域网共享时使用的物理网卡；可临时禁用无关 VPN/虚拟网卡再测。";
                items.Add(multi);
            }
            else if (host.Adapters.Count > 3)
            {
                DiagnosticItem multi = new DiagnosticItem();
                multi.Module = "LocalNetwork";
                multi.Item = "多网卡";
                multi.Status = DiagStatus.Ok;
                multi.CurrentValue = "适配器总数 " + host.Adapters.Count + "（有效出口 " + upWithValidIp + "）";
                multi.Description = "系统中有多块适配器（含虚拟网卡）属常见情况；当前有效出口数量正常，一般可忽略。";
                items.Add(multi);
            }

            if (gatewayCount > 1)
            {
                DiagnosticItem gw = new DiagnosticItem();
                gw.Module = "LocalNetwork";
                gw.Item = "多默认网关";
                gw.Status = DiagStatus.Warning;
                gw.CurrentValue = string.Join(", ", new List<string>(gateways).ToArray());
                gw.Description = "存在多个默认网关，可能导致路由异常。";
                gw.Recommendation = "保留正确网关，移除多余默认路由。";
                items.Add(gw);
            }

            // APIPA：有有效业务 IP 时不应标成“异常”
            if (apipaOnUp.Count > 0 && validIps.Count == 0)
            {
                DiagnosticItem apipa = new DiagnosticItem();
                apipa.Module = "LocalNetwork";
                apipa.Item = "APIPA地址";
                apipa.Status = DiagStatus.Abnormal;
                apipa.CurrentValue = string.Join("; ", apipaOnUp.ToArray());
                apipa.Description = "活动物理网卡只有 169.254.x.x，通常表示未获取到有效 DHCP/静态 IP。";
                apipa.Recommendation = "检查网线、DHCP 服务器或静态 IP 配置。";
                items.Add(apipa);
            }
            else if (apipaOnUp.Count > 0 || apipaOnDownOrVirtual.Count > 0)
            {
                DiagnosticItem apipa = new DiagnosticItem();
                apipa.Module = "LocalNetwork";
                apipa.Item = "APIPA地址";
                List<string> all = new List<string>();
                all.AddRange(apipaOnUp);
                all.AddRange(apipaOnDownOrVirtual);
                apipa.CurrentValue = string.Join("; ", all.ToArray());
                if (validIps.Count > 0)
                {
                    apipa.Status = DiagStatus.Ok;
                    apipa.Description = "检测到 169.254 链路本地地址，但本机已有有效 IPv4（"
                        + string.Join(", ", validIps.ToArray())
                        + "）。常见于虚拟网卡/未联网适配器，一般不影响局域网共享，可忽略。";
                }
                else
                {
                    apipa.Status = DiagStatus.Warning;
                    apipa.Description = "仅在虚拟或未连接适配器上看到 169.254 地址。";
                    apipa.Recommendation = "若无法访问共享，再检查物理网卡是否拿到正式 IP。";
                }
                items.Add(apipa);
            }

            IPAddress targetIp;
            if (!string.IsNullOrEmpty(targetHost) && TryResolveIPv4(targetHost, out targetIp))
            {
                bool sameSubnet = false;
                string matched = string.Empty;
                for (int i = 0; i < host.Adapters.Count; i++)
                {
                    AdapterInfo a = host.Adapters[i];
                    if (string.IsNullOrEmpty(a.IPv4) || string.IsNullOrEmpty(a.SubnetMask))
                        continue;
                    if (IsSameSubnet(a.IPv4, a.SubnetMask, targetIp.ToString()))
                    {
                        sameSubnet = true;
                        matched = a.Name + " (" + a.IPv4 + ")";
                        break;
                    }
                }

                DiagnosticItem subnet = new DiagnosticItem();
                subnet.Module = "LocalNetwork";
                subnet.Item = "网段匹配";
                subnet.CurrentValue = targetIp.ToString();
                if (sameSubnet)
                {
                    subnet.Status = DiagStatus.Ok;
                    subnet.Description = "目标 IP 与本机网卡处于同一子网: " + matched;
                }
                else
                {
                    subnet.Status = DiagStatus.Warning;
                    subnet.Description = "目标 IP 与本机已知网卡不在同一子网，可能跨网段/需路由。";
                    subnet.Recommendation = "确认路由可达；必要时检查网关与 VLAN。";
                }
                items.Add(subnet);

                // Best-effort route hint via route print parsing is heavy; keep simple note
                DiagnosticItem routeHint = new DiagnosticItem();
                routeHint.Module = "LocalNetwork";
                routeHint.Item = "出口提示";
                routeHint.Status = DiagStatus.Ok;
                routeHint.Description = sameSubnet
                    ? "同一子网访问，通常直接经匹配网卡发出。"
                    : "跨网段访问，请结合本机默认网关与路由表核对出口。";
                items.Add(routeHint);
            }

            for (int i = 0; i < host.Adapters.Count; i++)
            {
                AdapterInfo a = host.Adapters[i];
                if (!a.IsVirtualLikely) continue;
                DiagnosticItem virt = new DiagnosticItem();
                virt.Module = "LocalNetwork";
                virt.Item = "虚拟/VPN网卡";
                virt.Status = DiagStatus.Warning;
                virt.CurrentValue = a.Name;
                virt.Description = a.Description + " | " + a.IPv4 + " | " + a.OperationalStatus;
                virt.Recommendation = "若共享异常，可临时禁用该适配器后重测。";
                items.Add(virt);
            }

            return items;
        }

        private static List<AdapterInfo> CollectAdapters()
        {
            List<AdapterInfo> list = new List<AdapterInfo>();
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                for (int i = 0; i < nics.Length; i++)
                {
                    NetworkInterface nic = nics[i];
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    AdapterInfo a = new AdapterInfo();
                    a.Name = nic.Name;
                    a.Description = nic.Description;
                    a.OperationalStatus = nic.OperationalStatus.ToString();
                    a.IsVirtualLikely = IsVirtualLikely(nic.Name, nic.Description);

                    IPInterfaceProperties props = nic.GetIPProperties();
                    try
                    {
                        IPv4InterfaceProperties v4 = props.GetIPv4Properties();
                        a.DhcpEnabled = v4 != null && v4.IsDhcpEnabled;
                    }
                    catch
                    {
                        a.DhcpEnabled = false;
                    }

                    string preferredIp = null;
                    string preferredMask = "";
                    string fallbackApipa = null;
                    string fallbackMask = "";
                    foreach (UnicastIPAddressInformation uni in props.UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;
                        string ip = uni.Address.ToString();
                        string mask = "";
                        try { mask = uni.IPv4Mask != null ? uni.IPv4Mask.ToString() : ""; }
                        catch { mask = ""; }
                        a.AllIPv4s.Add(ip);
                        if (AdapterInfo.IsApipa(ip))
                        {
                            if (fallbackApipa == null)
                            {
                                fallbackApipa = ip;
                                fallbackMask = mask;
                            }
                        }
                        else if (preferredIp == null)
                        {
                            preferredIp = ip;
                            preferredMask = mask;
                        }
                    }
                    // 优先展示正式业务地址，避免把同网卡上的 169.254 当成“本机 IP”
                    if (preferredIp != null)
                    {
                        a.IPv4 = preferredIp;
                        a.SubnetMask = preferredMask;
                    }
                    else if (fallbackApipa != null)
                    {
                        a.IPv4 = fallbackApipa;
                        a.SubnetMask = fallbackMask;
                    }

                    List<string> gws = new List<string>();
                    foreach (GatewayIPAddressInformation g in props.GatewayAddresses)
                    {
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork)
                            gws.Add(g.Address.ToString());
                    }
                    a.Gateway = string.Join(", ", gws.ToArray());

                    List<string> dns = new List<string>();
                    foreach (IPAddress d in props.DnsAddresses)
                    {
                        if (d.AddressFamily == AddressFamily.InterNetwork)
                            dns.Add(d.ToString());
                    }
                    a.Dns = string.Join(", ", dns.ToArray());

                    list.Add(a);
                }
            }
            catch { }
            return list;
        }

        private static bool IsVirtualLikely(string name, string desc)
        {
            string s = ((name ?? "") + " " + (desc ?? "")).ToLowerInvariant();
            string[] keys = new string[] {
                "virtual", "vmware", "virtualbox", "hyper-v", "vethernet",
                "vpn", "tap", "tun", "wintun", "zerotier", "hamachi",
                "npcap", "loopback", "docker", "wsl", "virtio",
                "虚拟", "以太网适配器"
            };
            // "以太网适配器" alone is too broad on Chinese systems for physical NICs named that way.
            // Keep English virtual keywords primarily.
            for (int i = 0; i < keys.Length; i++)
            {
                if (keys[i] == "以太网适配器") continue;
                if (s.IndexOf(keys[i]) >= 0) return true;
            }
            return false;
        }

        public static bool TryResolveIPv4(string host, out IPAddress ip)
        {
            ip = null;
            if (string.IsNullOrEmpty(host)) return false;
            if (IPAddress.TryParse(host, out ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                return true;
            try
            {
                IPAddress[] addrs = Dns.GetHostAddresses(host);
                for (int i = 0; i < addrs.Length; i++)
                {
                    if (addrs[i].AddressFamily == AddressFamily.InterNetwork)
                    {
                        ip = addrs[i];
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool IsSameSubnet(string localIp, string mask, string targetIp)
        {
            try
            {
                byte[] a = IPAddress.Parse(localIp).GetAddressBytes();
                byte[] m = IPAddress.Parse(mask).GetAddressBytes();
                byte[] t = IPAddress.Parse(targetIp).GetAddressBytes();
                if (a.Length != 4 || m.Length != 4 || t.Length != 4) return false;
                for (int i = 0; i < 4; i++)
                {
                    if ((a[i] & m[i]) != (t[i] & m[i])) return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
