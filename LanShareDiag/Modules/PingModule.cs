using System;
using System.Net.NetworkInformation;
using LanShareDiag.Models;

namespace LanShareDiag.Modules
{
    public static class PingModule
    {
        public static DiagnosticItem PingHost(string host, int count, int timeoutMs)
        {
            DiagnosticItem item = new DiagnosticItem();
            item.Module = "IP";
            item.Item = "Ping";

            if (string.IsNullOrEmpty(host))
            {
                item.Status = DiagStatus.Error;
                item.Description = "未指定目标主机。";
                return item;
            }

            int sent = 0;
            int received = 0;
            long totalMs = 0;
            long minMs = long.MaxValue;
            long maxMs = 0;
            string lastError = string.Empty;

            try
            {
                using (Ping ping = new Ping())
                {
                    for (int i = 0; i < count; i++)
                    {
                        sent++;
                        try
                        {
                            PingReply reply = ping.Send(host, timeoutMs);
                            if (reply != null && reply.Status == IPStatus.Success)
                            {
                                received++;
                                totalMs += reply.RoundtripTime;
                                if (reply.RoundtripTime < minMs) minMs = reply.RoundtripTime;
                                if (reply.RoundtripTime > maxMs) maxMs = reply.RoundtripTime;
                            }
                            else
                            {
                                lastError = reply != null ? reply.Status.ToString() : "无响应";
                            }
                        }
                        catch (Exception ex)
                        {
                            lastError = ex.Message;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                item.Status = DiagStatus.Error;
                item.Description = "Ping 执行失败: " + ex.Message;
                item.Recommendation = "Ping 失败不一定代表主机离线（可能禁 ICMP）。请继续看 TCP 445 结果。";
                return item;
            }

            int lost = sent - received;
            double loss = sent == 0 ? 100 : (lost * 100.0 / sent);
            long avg = received > 0 ? totalMs / received : 0;

            item.CurrentValue = string.Format("发送{0}/成功{1}/丢包{2:0}%/平均{3}ms", sent, received, loss, avg);
            item.ElapsedMs = avg;

            if (received == 0)
            {
                item.Status = DiagStatus.Warning;
                item.Description = "未收到 ICMP 回复 (" + lastError + ")。目标可能离线，也可能禁用了 Ping。";
                item.Recommendation = "不要仅凭 Ping 失败判定设备离线，请继续检测 TCP 445/139。";
            }
            else if (loss > 0)
            {
                item.Status = DiagStatus.Warning;
                item.Description = string.Format("部分丢包。最小{0}ms 最大{1}ms 平均{2}ms。", minMs, maxMs, avg);
            }
            else
            {
                item.Status = DiagStatus.Ok;
                item.Description = string.Format("ICMP 可达。最小{0}ms 最大{1}ms 平均{2}ms。", minMs, maxMs, avg);
            }

            return item;
        }
    }
}
