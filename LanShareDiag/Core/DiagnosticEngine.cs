using System;
using System.ComponentModel;
using System.Net;
using LanShareDiag.Models;
using LanShareDiag.Modules;

namespace LanShareDiag.Core
{
    public sealed class DiagnosticEngine
    {
        private readonly BackgroundWorker _worker;
        private volatile bool _cancel;

        public event Action<string> ProgressChanged;
        public event Action<DiagnosticItem> ItemCompleted;
        public event Action<DiagnosisSession> Completed;

        public DiagnosticEngine()
        {
            _worker = new BackgroundWorker();
            _worker.WorkerSupportsCancellation = true;
            _worker.DoWork += Worker_DoWork;
            _worker.RunWorkerCompleted += Worker_RunWorkerCompleted;
        }

        public bool IsBusy
        {
            get { return _worker.IsBusy; }
        }

        public void Start(string targetHost, string sharePath)
        {
            if (_worker.IsBusy) return;
            _cancel = false;
            _worker.RunWorkerAsync(new string[] { targetHost ?? "", sharePath ?? "" });
        }

        public void Stop()
        {
            _cancel = true;
            if (_worker.IsBusy)
                _worker.CancelAsync();
        }

        private void Worker_DoWork(object sender, DoWorkEventArgs e)
        {
            string[] args = (string[])e.Argument;
            string targetHost = args[0].Trim();
            string sharePath = args[1].Trim();

            // Normalize inputs
            if (string.IsNullOrEmpty(targetHost) && !string.IsNullOrEmpty(sharePath))
            {
                string p = sharePath.Trim();
                if (p.StartsWith("\\\\"))
                {
                    p = p.Substring(2);
                    int slash = p.IndexOf('\\');
                    targetHost = slash >= 0 ? p.Substring(0, slash) : p;
                }
            }

            DiagnosisSession session = new DiagnosisSession();
            session.TargetHost = targetHost;
            session.SharePath = string.IsNullOrEmpty(sharePath)
                ? (string.IsNullOrEmpty(targetHost) ? "" : "\\\\" + targetHost)
                : sharePath;
            session.StartedAt = DateTime.Now;

            try
            {
                ReportProgress(session, "采集本机网络环境...");
                session.LocalHost = LocalNetworkModule.CollectLocalHost();
                AddItems(session, LocalNetworkModule.Diagnose(session.LocalHost, targetHost));
                if (_cancel) { e.Result = session; return; }

                ReportProgress(session, "Ping 检测...");
                DiagnosticItem ping = PingModule.PingHost(targetHost, 4, 2000);
                AddItem(session, ping);
                if (_cancel) { e.Result = session; return; }

                // Resolve host for TCP if needed
                string connectHost = targetHost;
                IPAddress ip;
                if (LocalNetworkModule.TryResolveIPv4(targetHost, out ip))
                    connectHost = ip.ToString();

                ReportProgress(session, "TCP 445 检测...");
                AddItem(session, TcpPortModule.TestTcp(connectHost, 445, 3000));
                if (_cancel) { e.Result = session; return; }

                ReportProgress(session, "TCP 139 检测...");
                AddItem(session, TcpPortModule.TestTcp(connectHost, 139, 3000));
                if (_cancel) { e.Result = session; return; }

                ReportProgress(session, "SMB 客户端组件检测...");
                int beforeSmb = session.Items.Count;
                SmbClientModule.Diagnose(session);
                RaiseFrom(session, beforeSmb);
                if (_cancel) { e.Result = session; return; }

                ReportProgress(session, "网络会话与凭据检测...");
                int before = session.Items.Count;
                NetworkSessionModule.Diagnose(session, targetHost);
                RaiseFrom(session, before);
                if (_cancel) { e.Result = session; return; }

                ReportProgress(session, "共享访问测试...");
                before = session.Items.Count;
                ShareAccessModule.Diagnose(session, targetHost, session.SharePath);
                RaiseFrom(session, before);
                if (_cancel) { e.Result = session; return; }

                ReportProgress(session, "事件日志摘要...");
                before = session.Items.Count;
                EventLogModule.Diagnose(session);
                RaiseFrom(session, before);

                ReportProgress(session, "生成智能诊断结论...");
                DecisionEngine.Analyze(session);
            }
            catch (Exception ex)
            {
                session.AddLog("诊断引擎异常: " + ex.Message);
                DiagnosticItem err = new DiagnosticItem();
                err.Module = "Engine";
                err.Item = "诊断流程";
                err.Status = DiagStatus.Error;
                err.Description = ex.Message;
                AddItem(session, err);
                try { DecisionEngine.Analyze(session); } catch { }
            }

            session.FinishedAt = DateTime.Now;
            e.Result = session;
        }

        private void Worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            DiagnosisSession session = e.Result as DiagnosisSession;
            if (session == null)
            {
                session = new DiagnosisSession();
                session.Conclusion = e.Error != null ? e.Error.Message : "诊断未完成。";
            }
            Action<DiagnosisSession> handler = Completed;
            if (handler != null) handler(session);
        }

        private void ReportProgress(DiagnosisSession session, string msg)
        {
            session.AddLog(msg);
            Action<string> handler = ProgressChanged;
            if (handler != null) handler(msg);
        }

        private void AddItem(DiagnosisSession session, DiagnosticItem item)
        {
            session.Items.Add(item);
            Action<DiagnosticItem> handler = ItemCompleted;
            if (handler != null) handler(item);
        }

        private void AddItems(DiagnosisSession session, System.Collections.Generic.List<DiagnosticItem> items)
        {
            for (int i = 0; i < items.Count; i++)
                AddItem(session, items[i]);
        }

        private void RaiseFrom(DiagnosisSession session, int startIndex)
        {
            for (int i = startIndex; i < session.Items.Count; i++)
            {
                Action<DiagnosticItem> handler = ItemCompleted;
                if (handler != null) handler(session.Items[i]);
            }
        }

    }
}
