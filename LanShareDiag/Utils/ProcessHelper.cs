using System;
using System.Diagnostics;
using System.Text;

namespace LanShareDiag.Utils
{
    public sealed class ProcessResult
    {
        public int ExitCode { get; set; }
        public string StdOut { get; set; }
        public string StdErr { get; set; }
        public bool TimedOut { get; set; }

        public ProcessResult()
        {
            StdOut = string.Empty;
            StdErr = string.Empty;
        }
    }

    public static class ProcessHelper
    {
        public static ProcessResult Run(string fileName, string arguments, int timeoutMs)
        {
            ProcessResult result = new ProcessResult();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = fileName;
                psi.Arguments = arguments;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                psi.StandardOutputEncoding = Encoding.GetEncoding(0);
                psi.StandardErrorEncoding = Encoding.GetEncoding(0);

                using (Process p = new Process())
                {
                    p.StartInfo = psi;
                    StringBuilder stdout = new StringBuilder();
                    StringBuilder stderr = new StringBuilder();
                    p.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
                    {
                        if (e.Data != null) stdout.AppendLine(e.Data);
                    };
                    p.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
                    {
                        if (e.Data != null) stderr.AppendLine(e.Data);
                    };

                    p.Start();
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();

                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch { }
                        result.TimedOut = true;
                        result.ExitCode = -1;
                    }
                    else
                    {
                        // Ensure async readers finish
                        p.WaitForExit();
                        result.ExitCode = p.ExitCode;
                    }

                    result.StdOut = stdout.ToString();
                    result.StdErr = stderr.ToString();
                }
            }
            catch (Exception ex)
            {
                result.ExitCode = -1;
                result.StdErr = ex.Message;
            }
            return result;
        }
    }
}
