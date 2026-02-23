using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace RansomGuard.Utils;

/// <summary>
/// Helpers for process inspection and termination.
/// </summary>
public static class ProcessHelper
{
    /// <summary>
    /// Attempt to find which process has a lock on the given file.
    /// Returns (processName, pid, processPath).
    /// </summary>
    public static (string Name, int Pid, string Path) TryGetLockingProcess(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return ("", 0, "");

            // Use Restart Manager API to detect file locks
            int result = NativeMethods.RmStartSession(out uint sessionHandle, 0, Guid.NewGuid().ToString());
            if (result != 0) return ("", 0, "");

            try
            {
                string[] files = { filePath };
                result = NativeMethods.RmRegisterResources(sessionHandle, (uint)files.Length, files, 0, null!, 0, null!);
                if (result != 0) return ("", 0, "");

                uint procInfoNeeded = 0;
                uint procInfoCount = 0;
                uint rebootReasons = 0;

                result = NativeMethods.RmGetList(sessionHandle, out procInfoNeeded, ref procInfoCount, null!, ref rebootReasons);

                if (result == 234 && procInfoNeeded > 0) // ERROR_MORE_DATA
                {
                    var procInfos = new NativeMethods.RM_PROCESS_INFO[procInfoNeeded];
                    procInfoCount = procInfoNeeded;

                    result = NativeMethods.RmGetList(sessionHandle, out procInfoNeeded, ref procInfoCount, procInfos, ref rebootReasons);
                    if (result == 0 && procInfoCount > 0)
                    {
                        var procInfo = procInfos[0];
                        try
                        {
                            var proc = Process.GetProcessById(procInfo.Process.dwProcessId);
                            return (proc.ProcessName, proc.Id, GetProcessPath(proc));
                        }
                        catch
                        {
                            return (procInfo.strAppName, procInfo.Process.dwProcessId, "");
                        }
                    }
                }

                return ("", 0, "");
            }
            finally
            {
                NativeMethods.RmEndSession(sessionHandle);
            }
        }
        catch
        {
            return ("", 0, "");
        }
    }

    /// <summary>
    /// Find the process with the highest I/O activity right now.
    /// This is the key fallback for when Restart Manager can't find file locks.
    /// </summary>
    public static (string Name, int Pid, string Path) FindHighIOProcess()
    {
        try
        {
            var candidates = Process.GetProcesses()
                .Select(p =>
                {
                    try
                    {
                        if (p.Id <= 4) return null;
                        if (p.SessionId == 0) return null; // Skip kernel/service processes

                        // Skip known safe system processes
                        var name = p.ProcessName.ToLowerInvariant();
                        if (IsKnownSafeProcess(name)) return null;

                        string? path = null;
                        try { path = p.MainModule?.FileName; } catch { }

                        // Use working set and thread count as proxy for "active" process
                        // Processes doing heavy I/O tend to have elevated thread counts
                        return new
                        {
                            Process = p,
                            Name = p.ProcessName,
                            Pid = p.Id,
                            Path = path ?? "",
                            PagedMem = p.PagedMemorySize64,
                            Threads = p.Threads.Count,
                            StartTime = TryGetStartTime(p)
                        };
                    }
                    catch { return null; }
                })
                .Where(x => x != null)
                .OrderByDescending(x => x!.Threads)
                .ThenByDescending(x => x!.PagedMem)
                .ToList();

            // Prefer recently started processes (within last 2 minutes) with high activity
            var recent = candidates
                .Where(c => c!.StartTime.HasValue && (DateTime.Now - c.StartTime.Value).TotalMinutes < 2)
                .FirstOrDefault();

            if (recent != null)
                return (recent.Name, recent.Pid, recent.Path);

            // Otherwise return the process with highest thread count (likely doing I/O)
            var top = candidates.FirstOrDefault();
            if (top != null)
                return (top.Name, top.Pid, top.Path);
        }
        catch { }
        return ("", 0, "");
    }

    /// <summary>
    /// Best-effort guess at which process is active in a directory.
    /// </summary>
    public static (string Name, int Pid, string Path) GuessActiveProcess(string directoryPath)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    if (proc.Id <= 4) continue;

                    var mainModule = proc.MainModule;
                    if (mainModule != null)
                    {
                        var modulePath = Path.GetDirectoryName(mainModule.FileName) ?? "";
                        if (directoryPath.StartsWith(modulePath, StringComparison.OrdinalIgnoreCase))
                        {
                            return (proc.ProcessName, proc.Id, mainModule.FileName);
                        }
                    }
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch { }

        return ("", 0, "");
    }

    /// <summary>Kill a process by PID.</summary>
    public static void KillProcess(int pid)
    {
        if (pid <= 0) return;
        using var process = Process.GetProcessById(pid);
        process.Kill(entireProcessTree: true);
    }

    /// <summary>Safely get the full path of a process executable.</summary>
    public static string GetProcessPath(Process proc)
    {
        try
        {
            return proc.MainModule?.FileName ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static DateTime? TryGetStartTime(Process p)
    {
        try { return p.StartTime; } catch { return null; }
    }

    private static bool IsKnownSafeProcess(string name)
    {
        return name is "explorer" or "svchost" or "csrss" or "wininit" or "winlogon"
            or "dwm" or "taskhostw" or "runtimebroker" or "searchhost"
            or "shellexperiencehost" or "startmenuexperiencehost"
            or "textinputhost" or "ctfmon" or "conhost" or "fontdrvhost"
            or "systemsettings" or "securityhealthservice" or "msedge"
            or "chrome" or "firefox" or "code" or "devenv"
            or "ransomguard" or "idle" or "system";
    }
}
