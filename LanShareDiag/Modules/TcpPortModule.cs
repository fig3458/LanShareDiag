using System;
using System.Diagnostics;
using System.Net.Sockets;
using LanShareDiag.Models;

namespace LanShareDiag.Modules
{
    public static class TcpPortModule
    {
        public static DiagnosticItem TestTcp(string host, int port, int timeoutMs)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "TCP";
            item.Item = "TCP " + port;

            if (string.IsNullOrEmpty(host))
            {
                item.Status = DiagStatus.Error;
                item.Description = "未指定目标主机。";
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
                        item.Status = DiagStatus.Abnormal;
                        item.CurrentValue = "超时";
                        item.Description = string.Format("连接 {0}:{1} 超时（{2}ms）。", host, port, timeoutMs);
                        item.Recommendation = RecommendForPort(port, "timeout");
                        try { client.Close(); } catch { }
                        return item;
                    }

                    try
                    {
                        client.EndConnect(ar);
                        sw.Stop();
                        item.ElapsedMs = sw.ElapsedMilliseconds;
                        item.Status = DiagStatus.Ok;
                        item.CurrentValue = "连接成功";
                        item.Description = string.Format("TCP {0} 连接成功，耗时 {1} ms。端口可达不代表 SMB 协商一定成功。", port, item.ElapsedMs);
                    }
                    catch (Exception ex)
                    {
                        sw.Stop();
                        item.ElapsedMs = sw.ElapsedMilliseconds;
                        item.Status = DiagStatus.Abnormal;
                        item.CurrentValue = "拒绝/失败";
                        item.Description = string.Format("连接 {0}:{1} 失败: {2}", host, port, ex.Message);
                        item.Recommendation = RecommendForPort(port, "refused");
                    }
                }
            }
            catch (SocketException sex)
            {
                sw.Stop();
                item.ElapsedMs = sw.ElapsedMilliseconds;
                item.Status = DiagStatus.Abnormal;
                item.CurrentValue = "SocketError " + sex.SocketErrorCode;
                item.ErrorCode = sex.ErrorCode;
                item.Description = sex.Message;
                item.Recommendation = RecommendForPort(port, "socket");
            }
            catch (Exception ex)
            {
                sw.Stop();
                item.ElapsedMs = sw.ElapsedMilliseconds;
                item.Status = DiagStatus.Error;
                item.Description = ex.Message;
            }

            return item;
        }

        private static string RecommendForPort(int port, string kind)
        {
            if (port == 445)
            {
                return "优先检查：目标是否启用文件和打印机共享；目标防火墙是否放行 SMB；本机安全软件是否拦截；目标 LanmanServer 是否运行；网络 ACL/VLAN。";
            }
            if (port == 139)
            {
                return "TCP 139 为 NetBIOS 会话端口。现代环境可主要依赖 445；若仅需 SMB 直连，445 成功即可。";
            }
            return "检查防火墙与目标服务监听状态。";
        }
    }
}
