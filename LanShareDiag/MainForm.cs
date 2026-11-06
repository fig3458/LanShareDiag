using System;
using System.Drawing;
using System.Windows.Forms;
using LanShareDiag.Core;
using LanShareDiag.Models;
using LanShareDiag.Repair;
using LanShareDiag.Report;
using LanShareDiag.Utils;

namespace LanShareDiag
{
    public class MainForm : Form
    {
        private TextBox _txtTarget;
        private TextBox _txtShare;
        private TextBox _txtUser;
        private TextBox _txtPassword;
        private Button _btnStart;
        private Button _btnStop;
        private Button _btnClear;
        private Button _btnExport;
        private Button _btnAdmin;
        private Label _lblStatus;
        private Label _lblAdmin;
        private ListView _lvResults;
        private TextBox _txtConclusion;
        private FlowLayoutPanel _repairPanel;
        private TextBox _txtLog;

        private DiagnosticEngine _engine;
        private DiagnosisSession _lastSession;
        private SplitContainer _mainSplit;
        private SplitContainer _bottomSplit;
        private SplitContainer _rightSplit;

        public MainForm()
        {
            Text = "局域网共享故障诊断工具  v2.0";
            Width = 1000;
            Height = 760;
            MinimumSize = new Size(880, 640);
            StartPosition = FormStartPosition.CenterScreen;
            Font = CreateUiFont(9F, FontStyle.Regular);
            BackColor = Color.FromArgb(245, 247, 250);
            try
            {
                string ico = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
                if (System.IO.File.Exists(ico))
                    Icon = new Icon(ico);
                else
                    Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch { }

            BuildUi();
            WireEngine();
            RefreshAdminLabel();
            Load += MainForm_Load;
        }

        private static Font CreateUiFont(float size, FontStyle style)
        {
            string[] families = new string[] { "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", "Tahoma" };
            for (int i = 0; i < families.Length; i++)
            {
                try { return new Font(families[i], size, style, GraphicsUnit.Point); }
                catch { }
            }
            return SystemFonts.MessageBoxFont;
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            // SplitContainer 必须在有实际尺寸后再设距离，否则会 InvalidOperationException 导致“双击没反应”
            SafeSetSplitter(_mainSplit, 0.55);
            SafeSetSplitter(_bottomSplit, 0.62);
            SafeSetSplitter(_rightSplit, 0.48);
        }

        private static void SafeSetSplitter(SplitContainer split, double ratio)
        {
            if (split == null) return;
            try
            {
                split.Panel1MinSize = 50;
                split.Panel2MinSize = 50;
                int total = split.Orientation == Orientation.Horizontal ? split.Height : split.Width;
                int distance = (int)(total * ratio);
                int min = split.Panel1MinSize;
                int max = total - split.Panel2MinSize - split.SplitterWidth;
                if (max < min) return;
                if (distance < min) distance = min;
                if (distance > max) distance = max;
                split.SplitterDistance = distance;
            }
            catch
            {
                // ignore layout edge cases
            }
        }

        private void BuildUi()
        {
            _mainSplit = new SplitContainer();
            _mainSplit.Dock = DockStyle.Fill;
            _mainSplit.Orientation = Orientation.Horizontal;
            // 先不要设 SplitterDistance / MinSize（控件尚未布局完成）
            Controls.Add(_mainSplit);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 138;
            top.Padding = new Padding(12);
            top.BackColor = Color.White;
            Controls.Add(top);

            Label title = new Label();
            title.Text = "Windows 局域网共享诊断 v2";
            title.Font = CreateUiFont(14F, FontStyle.Bold);
            title.AutoSize = true;
            title.Location = new Point(12, 10);
            top.Controls.Add(title);

            _lblAdmin = new Label();
            _lblAdmin.AutoSize = true;
            _lblAdmin.Location = new Point(280, 16);
            top.Controls.Add(_lblAdmin);

            _btnAdmin = new Button();
            _btnAdmin.Text = "以管理员运行";
            _btnAdmin.Location = new Point(820, 10);
            _btnAdmin.Size = new Size(120, 28);
            _btnAdmin.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnAdmin.Click += BtnAdmin_Click;
            top.Controls.Add(_btnAdmin);

            Label l1 = new Label();
            l1.Text = "目标 IP/主机名:";
            l1.Location = new Point(12, 48);
            l1.AutoSize = true;
            top.Controls.Add(l1);

            _txtTarget = new TextBox();
            _txtTarget.Location = new Point(120, 44);
            _txtTarget.Width = 220;
            _txtTarget.Text = "";
            top.Controls.Add(_txtTarget);

            Label l2 = new Label();
            l2.Text = "共享路径:";
            l2.Location = new Point(360, 48);
            l2.AutoSize = true;
            top.Controls.Add(l2);

            _txtShare = new TextBox();
            _txtShare.Location = new Point(430, 44);
            _txtShare.Width = 300;
            _txtShare.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            top.Controls.Add(_txtShare);

            Label l3 = new Label();
            l3.Text = "探测账号(可选):";
            l3.Location = new Point(12, 74);
            l3.AutoSize = true;
            top.Controls.Add(l3);

            _txtUser = new TextBox();
            _txtUser.Location = new Point(120, 70);
            _txtUser.Width = 160;
            top.Controls.Add(_txtUser);

            Label l4 = new Label();
            l4.Text = "密码:";
            l4.Location = new Point(290, 74);
            l4.AutoSize = true;
            top.Controls.Add(l4);

            _txtPassword = new TextBox();
            _txtPassword.Location = new Point(330, 70);
            _txtPassword.Width = 160;
            _txtPassword.UseSystemPasswordChar = true;
            top.Controls.Add(_txtPassword);

            Label l5 = new Label();
            l5.Text = "密码仅用于本次 IPC$ 探测，不写入报告。";
            l5.AutoSize = true;
            l5.ForeColor = Color.FromArgb(100, 100, 100);
            l5.Location = new Point(500, 74);
            top.Controls.Add(l5);

            _btnStart = MakeButton("开始诊断", 120, 44);
            _btnStart.Location = new Point(12, 102);
            _btnStart.Click += BtnStart_Click;
            top.Controls.Add(_btnStart);

            _btnStop = MakeButton("停止", 80, 44);
            _btnStop.Location = new Point(140, 102);
            _btnStop.Enabled = false;
            _btnStop.Click += BtnStop_Click;
            top.Controls.Add(_btnStop);

            _btnClear = MakeButton("清空结果", 90, 44);
            _btnClear.Location = new Point(228, 102);
            _btnClear.Click += BtnClear_Click;
            top.Controls.Add(_btnClear);

            _btnExport = MakeButton("导出报告", 90, 44);
            _btnExport.Location = new Point(326, 102);
            _btnExport.Click += BtnExport_Click;
            top.Controls.Add(_btnExport);

            _lblStatus = new Label();
            _lblStatus.Text = "就绪 — v2 增强策略/出口/鉴权探测；修复需确认。";
            _lblStatus.AutoSize = true;
            _lblStatus.Location = new Point(430, 108);
            top.Controls.Add(_lblStatus);

            // Hint sync share path
            _txtTarget.TextChanged += delegate
            {
                if (string.IsNullOrEmpty(_txtShare.Text) || _txtShare.Text.StartsWith("\\\\"))
                {
                    if (!string.IsNullOrEmpty(_txtTarget.Text.Trim()))
                        _txtShare.Text = "\\\\" + _txtTarget.Text.Trim();
                }
            };

            // Results list
            GroupBox gbResults = new GroupBox();
            gbResults.Text = "实时诊断结果";
            gbResults.Dock = DockStyle.Fill;
            gbResults.Padding = new Padding(8);

            _lvResults = new ListView();
            _lvResults.Dock = DockStyle.Fill;
            _lvResults.View = View.Details;
            _lvResults.FullRowSelect = true;
            _lvResults.GridLines = true;
            _lvResults.Columns.Add("检测项目", 160);
            _lvResults.Columns.Add("状态", 70);
            _lvResults.Columns.Add("详情", 680);
            gbResults.Controls.Add(_lvResults);
            _mainSplit.Panel1.Controls.Add(gbResults);

            _bottomSplit = new SplitContainer();
            _bottomSplit.Dock = DockStyle.Fill;
            _bottomSplit.Orientation = Orientation.Vertical;
            _mainSplit.Panel2.Controls.Add(_bottomSplit);

            GroupBox gbConclusion = new GroupBox();
            gbConclusion.Text = "故障诊断结论";
            gbConclusion.Dock = DockStyle.Fill;
            gbConclusion.Padding = new Padding(8);
            _bottomSplit.Panel1.Controls.Add(gbConclusion);

            _txtConclusion = new TextBox();
            _txtConclusion.Dock = DockStyle.Fill;
            _txtConclusion.Multiline = true;
            _txtConclusion.ScrollBars = ScrollBars.Vertical;
            _txtConclusion.ReadOnly = true;
            _txtConclusion.BackColor = Color.White;
            gbConclusion.Controls.Add(_txtConclusion);

            _rightSplit = new SplitContainer();
            _rightSplit.Dock = DockStyle.Fill;
            _rightSplit.Orientation = Orientation.Horizontal;
            _bottomSplit.Panel2.Controls.Add(_rightSplit);

            GroupBox gbRepair = new GroupBox();
            gbRepair.Text = "修复操作（需确认）";
            gbRepair.Dock = DockStyle.Fill;
            gbRepair.Padding = new Padding(8);
            _rightSplit.Panel1.Controls.Add(gbRepair);

            _repairPanel = new FlowLayoutPanel();
            _repairPanel.Dock = DockStyle.Fill;
            _repairPanel.FlowDirection = FlowDirection.TopDown;
            _repairPanel.WrapContents = false;
            _repairPanel.AutoScroll = true;
            gbRepair.Controls.Add(_repairPanel);

            GroupBox gbLog = new GroupBox();
            gbLog.Text = "过程日志";
            gbLog.Dock = DockStyle.Fill;
            gbLog.Padding = new Padding(8);
            _rightSplit.Panel2.Controls.Add(gbLog);

            _txtLog = new TextBox();
            _txtLog.Dock = DockStyle.Fill;
            _txtLog.Multiline = true;
            _txtLog.ScrollBars = ScrollBars.Vertical;
            _txtLog.ReadOnly = true;
            try { _txtLog.Font = new Font("Consolas", 8.5F); }
            catch { _txtLog.Font = Font; }
            _txtLog.BackColor = Color.FromArgb(30, 30, 30);
            _txtLog.ForeColor = Color.FromArgb(200, 230, 200);
            gbLog.Controls.Add(_txtLog);
        }

        private Button MakeButton(string text, int w, int hIgnored)
        {
            Button b = new Button();
            b.Text = text;
            b.Size = new Size(w, 28);
            b.FlatStyle = FlatStyle.System;
            return b;
        }

        private void WireEngine()
        {
            _engine = new DiagnosticEngine();
            _engine.ProgressChanged += msg =>
            {
                BeginInvoke(new Action(() =>
                {
                    _lblStatus.Text = msg;
                    AppendLog(msg);
                }));
            };
            _engine.ItemCompleted += item =>
            {
                BeginInvoke(new Action(() => AddResultRow(item)));
            };
            _engine.Completed += session =>
            {
                BeginInvoke(new Action(() => OnDiagnosisCompleted(session)));
            };
        }

        private void BtnStart_Click(object sender, EventArgs e)
        {
            string target = _txtTarget.Text.Trim();
            string share = _txtShare.Text.Trim();
            if (string.IsNullOrEmpty(target) && string.IsNullOrEmpty(share))
            {
                MessageBox.Show(this, "请输入目标 IP/主机名或共享路径。", "提示",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            ClearResults(false);
            _btnStart.Enabled = false;
            _btnStop.Enabled = true;
            _btnExport.Enabled = false;
            _lblStatus.Text = "诊断进行中...";
            _engine.Start(target, share, _txtUser.Text.Trim(), _txtPassword.Text);
        }

        private void BtnStop_Click(object sender, EventArgs e)
        {
            _engine.Stop();
            _lblStatus.Text = "正在停止...";
        }

        private void BtnClear_Click(object sender, EventArgs e)
        {
            ClearResults(true);
        }

        private void ClearResults(bool clearInputs)
        {
            _lvResults.Items.Clear();
            _txtConclusion.Clear();
            _txtLog.Clear();
            _repairPanel.Controls.Clear();
            _lastSession = null;
            if (clearInputs)
            {
                // keep target
            }
            _lblStatus.Text = "就绪";
            _btnExport.Enabled = false;
        }

        private void BtnExport_Click(object sender, EventArgs e)
        {
            if (_lastSession == null)
            {
                MessageBox.Show(this, "没有可导出的诊断结果。", "提示",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (SaveFileDialog dlg = new SaveFileDialog())
            {
                dlg.Filter = "文本报告 (*.txt)|*.txt|HTML 报告 (*.html)|*.html|JSON 报告 (*.json)|*.json";
                dlg.FileName = "LanShareDiag_" + DateTime.Now.ToString("yyyyMMdd_HHmmss");
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    string path = dlg.FileName;
                    if (path.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
                        ReportExporter.ExportHtml(_lastSession, path);
                    else if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                        ReportExporter.ExportJson(_lastSession, path);
                    else
                        ReportExporter.ExportTxt(_lastSession, path);
                    MessageBox.Show(this, "已导出:\r\n" + path, "导出成功",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "导出失败",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void BtnAdmin_Click(object sender, EventArgs e)
        {
            if (AdminHelper.IsAdministrator())
            {
                MessageBox.Show(this, "当前已是管理员权限。", "提示",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (AdminHelper.TryRelaunchAsAdmin())
            {
                Close();
            }
            else
            {
                MessageBox.Show(this, "未能提权，用户可能取消了 UAC。", "提示",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void OnDiagnosisCompleted(DiagnosisSession session)
        {
            _lastSession = session;
            _btnStart.Enabled = true;
            _btnStop.Enabled = false;
            _btnExport.Enabled = true;
            _lblStatus.Text = "诊断完成";
            _txtConclusion.Text = session.Conclusion;
            if (session.Recommendations != null && session.Recommendations.Count > 0)
            {
                _txtConclusion.AppendText("\r\n\r\n—— 建议 ——\r\n");
                for (int i = 0; i < session.Recommendations.Count; i++)
                    _txtConclusion.AppendText((i + 1) + ". " + session.Recommendations[i] + "\r\n");
            }

            for (int i = 0; i < session.Logs.Count; i++)
            {
                // already partially logged; ensure full
            }

            BuildRepairButtons(session);
            AppendLog("诊断完成。");
        }

        private void BuildRepairButtons(DiagnosisSession session)
        {
            _repairPanel.Controls.Clear();
            if (session.RepairSuggestions == null) return;

            for (int i = 0; i < session.RepairSuggestions.Count; i++)
            {
                RepairSuggestion sug = session.RepairSuggestions[i];
                Button b = new Button();
                b.Text = sug.Title + (sug.RequiresAdmin ? " *" : "");
                b.Width = Math.Max(200, _repairPanel.ClientSize.Width - 30);
                b.Height = 30;
                b.Margin = new Padding(3);
                b.Tag = sug;
                b.Click += RepairButton_Click;
                ToolTip tip = new ToolTip();
                tip.SetToolTip(b, sug.Description + (sug.RequiresAdmin ? "\n需要管理员权限" : "") + (sug.Dangerous ? "\n需二次确认" : ""));
                _repairPanel.Controls.Add(b);
            }

            Button recheck = new Button();
            recheck.Text = "重新检测";
            recheck.Width = Math.Max(200, _repairPanel.ClientSize.Width - 30);
            recheck.Height = 30;
            recheck.Click += BtnStart_Click;
            _repairPanel.Controls.Add(recheck);
        }

        private void RepairButton_Click(object sender, EventArgs e)
        {
            Button b = sender as Button;
            RepairSuggestion sug = b != null ? b.Tag as RepairSuggestion : null;
            if (sug == null) return;

            if (sug.RequiresAdmin && !AdminHelper.IsAdministrator())
            {
                DialogResult ask = MessageBox.Show(this,
                    "该操作需要管理员权限。是否立即以管理员身份重启本程序？",
                    "需要提权", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (ask == DialogResult.Yes)
                {
                    if (AdminHelper.TryRelaunchAsAdmin()) Close();
                }
                return;
            }

            if (!sug.Id.StartsWith("open_") && !sug.Id.StartsWith("clear_"))
            {
                DialogResult confirm = MessageBox.Show(this,
                    "即将执行修复:\r\n" + sug.Title + "\r\n\r\n" + sug.Description + "\r\n\r\n是否继续？",
                    "确认修复", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (confirm != DialogResult.Yes) return;
            }

            string target = _lastSession != null ? _lastSession.TargetHost : _txtTarget.Text.Trim();
            RepairResult result = RepairActions.Execute(sug.Id, target);
            AppendLog("[修复] " + sug.Title + " => " + (result.Success ? "成功" : "失败"));
            AppendLog(result.Message);
            if (!string.IsNullOrEmpty(result.Before) || !string.IsNullOrEmpty(result.After))
                AppendLog("变更: " + result.Before + " -> " + result.After);

            MessageBox.Show(this,
                (result.Success ? "执行完成。\r\n\r\n" : "执行未完全成功。\r\n\r\n") + result.Message,
                sug.Title,
                MessageBoxButtons.OK,
                result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void AddResultRow(DiagnosticItem item)
        {
            ListViewItem row = new ListViewItem(item.Item);
            row.SubItems.Add(item.StatusText);
            string detail = item.Description;
            if (!string.IsNullOrEmpty(item.CurrentValue))
                detail = item.CurrentValue + " — " + detail;
            detail = (detail ?? "").Replace("\r\n", " ");
            row.SubItems.Add(detail);
            switch (item.Status)
            {
                case DiagStatus.Ok:
                    row.ForeColor = Color.FromArgb(0, 120, 50);
                    break;
                case DiagStatus.Warning:
                    row.ForeColor = Color.FromArgb(160, 100, 0);
                    break;
                case DiagStatus.Abnormal:
                case DiagStatus.Error:
                    row.ForeColor = Color.FromArgb(180, 0, 30);
                    break;
            }
            _lvResults.Items.Add(row);
            row.EnsureVisible();
        }

        private void AppendLog(string msg)
        {
            _txtLog.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + msg + "\r\n");
        }

        private void RefreshAdminLabel()
        {
            bool admin = AdminHelper.IsAdministrator();
            _lblAdmin.Text = admin ? "权限: 管理员" : "权限: 标准用户（只读诊断可用）";
            _lblAdmin.ForeColor = admin ? Color.FromArgb(0, 120, 50) : Color.FromArgb(120, 80, 0);
            _btnAdmin.Visible = !admin;
        }
    }
}
