using System;
using Microsoft.Win32;

namespace LanShareDiag.Utils
{
    public static class OsHelper
    {
        public static string GetFriendlyOsName()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        string product = Convert.ToString(key.GetValue("ProductName", "Windows"));
                        string build = Convert.ToString(key.GetValue("CurrentBuildNumber", ""));
                        string display = Convert.ToString(key.GetValue("DisplayVersion", ""));
                        if (!string.IsNullOrEmpty(display))
                            return product + " " + display + " (Build " + build + ")";
                        return product + " (Build " + build + ")";
                    }
                }
            }
            catch { }
            return Environment.OSVersion.ToString();
        }

        public static string GetBuildNumber()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                        return Convert.ToString(key.GetValue("CurrentBuildNumber", ""));
                }
            }
            catch { }
            return string.Empty;
        }

        public static bool IsWindows7OrOlder()
        {
            // Win7 = 6.1
            Version v = Environment.OSVersion.Version;
            return v.Major < 6 || (v.Major == 6 && v.Minor <= 1);
        }

        public static bool IsWindows10OrLater()
        {
            Version v = Environment.OSVersion.Version;
            // Win10 reports as 6.2/6.3 unless manifest; with manifest may be 10.0
            if (v.Major >= 10) return true;
            string build = GetBuildNumber();
            int b;
            if (int.TryParse(build, out b) && b >= 10240) return true;
            return false;
        }

        public static string GetArchitecture()
        {
            return Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";
        }
    }
}
