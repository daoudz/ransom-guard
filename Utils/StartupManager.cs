using System;
using Microsoft.Win32;

namespace RansomGuard.Utils;

/// <summary>
/// Manages auto-start registration via Windows Registry Run key.
/// </summary>
public static class StartupManager
{
    private const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "RansomGuard";

    /// <summary>Check whether RansomGuard is set to start with Windows.</summary>
    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, false);
            return key?.GetValue(AppName) != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Register RansomGuard to start automatically with Windows.</summary>
    public static void Enable()
    {
        try
        {
            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exePath)) return;

            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            key?.SetValue(AppName, $"\"{exePath}\"");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[StartupManager] Failed to enable: {ex.Message}");
        }
    }

    /// <summary>Remove RansomGuard from Windows auto-start.</summary>
    public static void Disable()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            key?.DeleteValue(AppName, false);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[StartupManager] Failed to disable: {ex.Message}");
        }
    }
}
