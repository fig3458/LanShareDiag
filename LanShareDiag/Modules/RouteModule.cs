using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using LanShareDiag.Models;

namespace LanShareDiag.Modules
{
    /// <summary>
    /// P0：探测访问目标时实际使用的本机出口 IP（连 445 看 LocalEndPoint）
    /// </summary>
    public static class RouteModule
    {
        public static DiagnosticItem ProbeEgress(string host, int port, int timeoutMs)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "Route";
            item.Item = "访问出口网卡";

            if (string.IsNullOrEmpty(host))
            {
                item.Status = DiagStatus.Error;
                item.Description = "未指定目标。";
                return item;
            }

            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(host, port, null, null);
                    bool ok = ar.AsyncWaitHandle.WaitOne(timeoutMs, false);
                    if (!ok)
                    {
                        sw.Stop();
                        item.ElapsedMs = sw.ElapsedMilliseconds;
                        item.Status = DiagStatus.Warning;
                        item.CurrentValue = "连接超时，未能观察出口";
                        item.Description = "TCP " + port + " 超时，无法从已建立连接读取本机出口。请结合路由/防火墙继续查。";
                        try { client.Close(); } catch { }
                        return item;
                    }

                    try
                    {
                        client.EndConnect(ar);
                    }
                    catch (Exception ex)
                    {
                        sw.Stop();
                        item.ElapsedMs = sw.ElapsedMilliseconds;
                        item.Status = DiagStatus.Warning;
                        item.Description = "连接未成功，无法可靠判定出口: " + ex.Message;
                        return item;
                    }

                    sw.Stop();
                    item.ElapsedMs = sw.ElapsedMilliseconds;
                    IPEndPoint local = client.Client.LocalEndPoint as IPEndPoint;
                    IPEndPoint remote = client.Client.RemoteEndPoint as IPEndPoint;
                    if (local != null)
                    {
                        item.CurrentValue = local.Address + " -> " + (remote != null ? remote.Address.ToString() : host);
                        item.Status = DiagStatus.Ok;
                        item.Description = "访问目标 TCP " + port + " 时，本机实际出口为 "
                            + local.Address + "。若该地址不属于预期物理网卡，可能走了 VPN/虚拟网卡。";
                    }
                    else
                    {
                        item.Status = DiagStatus.Warning;
                        item.Description = "已连接但无法读取 LocalEndPoint。";
                    }
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                item.ElapsedMs = sw.ElapsedMilliseconds;
                item.Status = DiagStatus.Warning;
                item.Description = ex.Message;
            }

            return item;
        }
    }
}
