using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using RansomGuard.Utils;

namespace RansomGuard.Core;

/// <summary>
/// Represents a single file system activity event.
/// </summary>
public sealed class FileActivityEvent
{
    public string FilePath { get; init; } = "";
    public string? OldPath { get; init; }
    public WatcherChangeTypes ChangeType { get; init; }
    public char DriveLetter { get; init; }
    public string OldExtension { get; init; } = "";
    public string NewExtension { get; init; } = "";
    public bool IsExtensionChange { get; init; }
    public DateTime Timestamp { get; init; }
}

/// <summary>
/// Per-directory activity statistics within a sliding time window.
/// </summary>
internal sealed class DirectoryStats
{
    public string DirectoryPath { get; set; } = "";
    public List<DateTime> WriteTimestamps { get; } = new();
    public List<DateTime> RenameTimestamps { get; } = new();
    public List<DateTime> ExtensionChangeTimestamps { get; } = new();
    public List<string> ExtensionChanges { get; } = new();
    public HashSet<string> UniqueExtensionsNew { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<char> DrivesAccessed { get; } = new();
    public string LastTriggerFile { get; set; } = "";
    public DateTime LastActivity { get; set; }
    public HashSet<string> AlertedHeuristics { get; } = new();

    // Attributed process (filled when threshold is about to fire)
    public string ProcessName { get; set; } = "";
    public int ProcessId { get; set; }
    public string ProcessPath { get; set; } = "";

    public int TotalEvents => WriteTimestamps.Count + RenameTimestamps.Count;

    /// <summary>Prune events older than the window.</summary>
    public void Prune(TimeSpan window)
    {
        var cutoff = DateTime.UtcNow - window;
        WriteTimestamps.RemoveAll(t => t < cutoff);
        RenameTimestamps.RemoveAll(t => t < cutoff);
        ExtensionChangeTimestamps.RemoveAll(t => t < cutoff);
    }
}

/// <summary>
/// Tracks file activity per-directory and runs detection heuristics.
///
/// Detection philosophy — avoid false positives from browsers/AV/IDEs by:
///   1. Raising the count thresholds to levels that only ransomware-scale I/O reaches.
///   2. Using a wider analysis window (30 s) so brief legitimate bursts don't accumulate.
///   3. Requiring *multiple combined signals* before firing MassWrite alerts.
///   4. Filtering well-known benign paths (browser caches, AV dirs, package managers, etc.).
///   5. Requiring that extension changes target a *consistent unknown extension* pattern
///      rather than any extension switch (which IDEs do constantly).
/// </summary>
public sealed class ActivityTracker
{
    // ── Heuristic thresholds ───────────────────────────────────────────────────
    // Extension-change heuristic: N different filenames renamed to an UNKNOWN extension
    private const int ExtensionChangeThreshold = 10;

    // Bulk-rename heuristic: N renames within the window (no extension context)
    private const int BulkRenameThreshold = 20;

    // Mass-write heuristic: N write events — BUT only fires when combined with
    // at least one other signal (renames OR extension changes). Standalone high
    // write counts from browsers/AV will NOT fire.
    private const int MassWriteThreshold = 80;

    // How many *distinct* new extensions must appear in extension-change events
    // before it looks like encryption (ransomware picks one ext; IDEs rename to many)
    private const int SuspiciousNewExtensionCount = 1; // ≥ 1 consistent unknown ext
    private const int MaxNewExtensionVariants = 3;     // if > 3 unique new exts → likely IDE/tools, not ransomware

    // Multi-drive heuristic: writing to this many drives within the window
    private const int MultiDriveThreshold = 3;

    // Minimum write count that must accompany renames before a combined alert fires
    private const int CombinedWriteMinimum = 20;

    // ── Time windows ──────────────────────────────────────────────────────────
    private static readonly TimeSpan AnalysisWindow  = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan CooldownPeriod  = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan StaleTimeout    = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MultiDriveWindow = TimeSpan.FromSeconds(30);

    // ── Known-benign extension pairs (IDE saves, Office temp files, AV, etc.) ─
    // If EVERY extension change in a directory matches one of these pairs, skip.
    private static readonly HashSet<string> BenignExtensionChanges = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tmp→.docx", ".tmp→.xlsx", ".tmp→.pptx", ".tmp→.pdf",
        ".tmp→.doc",  ".tmp→.xls",
        "→.tmp", "→.bak", "→.swp", "→.crdownload", "→.partial",
        ".crdownload→.exe", ".crdownload→.zip", ".crdownload→.msi",
        ".partial→.mp4", ".partial→.mkv",
        ".log→.log1",  // common log rotation
    };

    // ── Known-benign new extensions (if all new-exts are in this set, skip) ──
    private static readonly HashSet<string> BenignNewExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tmp", ".bak", ".log", ".log1", ".log2", ".swp", ".swo",
        ".crdownload", ".partial", ".download",
        ".lnk", ".pf", // prefetch / shortcuts
        ".db", ".db-wal", ".db-shm",
        ".json", ".xml", ".config",
    };

    // ── State ─────────────────────────────────────────────────────────────────
    private readonly ConcurrentDictionary<string, DirectoryStats> _directoryStats
        = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentBag<FileActivityEvent> _pendingEvents = new();
    private readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _alertCooldowns = new();
    private readonly ConcurrentDictionary<char, DateTime> _globalDriveAccess = new();
    private readonly object _lock = new();

    // ── Public API ────────────────────────────────────────────────────────────

    public void RecordEvent(FileActivityEvent evt) => _pendingEvents.Add(evt);

    public void Whitelist(string processName)
    {
        lock (_lock) { _whitelist.Add(processName); }
    }

    public List<string> GetWhitelist()
    {
        lock (_lock) { return new List<string>(_whitelist); }
    }

    public void RemoveFromWhitelist(string processName)
    {
        lock (_lock) { _whitelist.Remove(processName); }
    }

    public void Clear()
    {
        _directoryStats.Clear();
        _globalDriveAccess.Clear();
        while (_pendingEvents.TryTake(out _)) { }
    }

    public Dictionary<string, int> GetActiveDirectories()
    {
        var result = new Dictionary<string, int>();
        foreach (var (dir, stats) in _directoryStats)
            if (stats.TotalEvents > 0)
                result[dir] = stats.TotalEvents;
        return result;
    }

    /// <summary>Creates an immediate alert for honeypot file modification.</summary>
    public SuspiciousActivityEventArgs? CreateHoneypotAlert(string filePath)
    {
        var (procName, procId, procPath) = ProcessHelper.TryGetLockingProcess(filePath);
        if (string.IsNullOrEmpty(procName))
            (procName, procId, procPath) = ProcessHelper.FindHighIOProcess();
        if (string.IsNullOrEmpty(procName))
            procName = "Unknown Process";

        lock (_lock)
        {
            if (_whitelist.Contains(procName)) return null;
        }

        return new SuspiciousActivityEventArgs
        {
            ProcessName  = procName,
            ProcessId    = procId,
            ProcessPath  = procPath,
            Description  = "⚠ HONEYPOT FILE TOUCHED — Possible ransomware encryption attempt!",
            TriggerFile  = filePath,
            HeuristicName = "Honeypot",
            DetectedAt   = DateTime.Now
        };
    }

    // ── Core analysis loop ────────────────────────────────────────────────────

    /// <summary>
    /// Drain pending events, update per-directory stats, and run heuristic checks.
    /// </summary>
    public List<SuspiciousActivityEventArgs> Analyze()
    {
        var alerts = new List<SuspiciousActivityEventArgs>();

        // Drain pending events
        var events = new List<FileActivityEvent>();
        while (_pendingEvents.TryTake(out var evt))
            events.Add(evt);

        // Prune stale directories
        var staleKeys = _directoryStats
            .Where(kv => DateTime.UtcNow - kv.Value.LastActivity > StaleTimeout)
            .Select(kv => kv.Key).ToList();
        foreach (var key in staleKeys)
            _directoryStats.TryRemove(key, out _);

        // Prune old timestamps even when idle
        if (events.Count == 0)
        {
            foreach (var stats in _directoryStats.Values)
                stats.Prune(AnalysisWindow);
            return alerts;
        }

        // Group events by parent directory
        foreach (var evt in events)
        {
            var dir = Path.GetDirectoryName(evt.FilePath) ?? "";
            if (string.IsNullOrEmpty(dir)) continue;

            var stats = _directoryStats.GetOrAdd(dir, _ => new DirectoryStats { DirectoryPath = dir });
            stats.LastTriggerFile = evt.FilePath;
            stats.LastActivity    = evt.Timestamp;

            switch (evt.ChangeType)
            {
                case WatcherChangeTypes.Renamed:
                    stats.RenameTimestamps.Add(evt.Timestamp);
                    if (evt.IsExtensionChange)
                    {
                        stats.ExtensionChangeTimestamps.Add(evt.Timestamp);
                        stats.ExtensionChanges.Add($"{evt.OldExtension}→{evt.NewExtension}");
                        if (!string.IsNullOrEmpty(evt.NewExtension))
                            stats.UniqueExtensionsNew.Add(evt.NewExtension);
                    }
                    break;

                case WatcherChangeTypes.Created:
                case WatcherChangeTypes.Changed:
                case WatcherChangeTypes.Deleted:
                    stats.WriteTimestamps.Add(evt.Timestamp);
                    break;
            }

            stats.DrivesAccessed.Add(evt.DriveLetter);
            _globalDriveAccess[evt.DriveLetter] = evt.Timestamp;
        }

        // Run heuristics per directory
        foreach (var (dirKey, stats) in _directoryStats)
        {
            stats.Prune(AnalysisWindow);

            // Respect per-directory cooldown
            if (_alertCooldowns.TryGetValue(dirKey, out var lastAlert)
                && DateTime.UtcNow - lastAlert < CooldownPeriod)
                continue;

            SuspiciousActivityEventArgs? alert = null;

            // ── Heuristic 1: Extension changes ──────────────────────────────
            // Fires when: N+ files renamed to a *consistent* unknown extension.
            // Suppressed when: all new extensions are benign, OR there are too
            // many different new extensions (IDE/compiler behaviour), OR the
            // responsible process is whitelisted.
            if (alert == null
                && stats.ExtensionChangeTimestamps.Count >= ExtensionChangeThreshold
                && !stats.AlertedHeuristics.Contains("ExtensionChange"))
            {
                if (IsExtensionChangePatternSuspicious(stats))
                {
                    AttributeProcess(stats);
                    bool wl1; lock (_lock) { wl1 = _whitelist.Contains(stats.ProcessName); }
                    if (!wl1)
                    {
                        var commonChange = GetMostCommonExtChange(stats.ExtensionChanges);
                        alert = CreateAlert(stats, "ExtensionChange",
                            $"Mass file extension change — {stats.ExtensionChangeTimestamps.Count} files changed ({commonChange}). Possible encryption!");
                    }
                }
            }

            // ── Heuristic 2: Bulk renames + writes (combined signal) ─────────
            // Fires when: bulk renames AND a meaningful number of writes occur
            // together. Standalone renames (e.g., file manager sort/rename) need
            // to reach a much higher bar without companion write activity.
            if (alert == null
                && stats.RenameTimestamps.Count >= BulkRenameThreshold
                && !stats.AlertedHeuristics.Contains("BulkRename"))
            {
                bool hasCompanionWrites = stats.WriteTimestamps.Count >= CombinedWriteMinimum;
                if (hasCompanionWrites)
                {
                    AttributeProcess(stats);
                    bool wl2; lock (_lock) { wl2 = _whitelist.Contains(stats.ProcessName); }
                    if (!wl2)
                        alert = CreateAlert(stats, "BulkRename",
                            $"Bulk rename + write activity — {stats.RenameTimestamps.Count} renames, {stats.WriteTimestamps.Count} writes in {AnalysisWindow.TotalSeconds}s in {stats.DirectoryPath}");
                }
            }

            // ── Heuristic 3: Mass write — only with a companion signal ───────
            // Browsers and AV routinely write 80-200 files per 30 s. We only
            // flag this when it is accompanied by suspicious renames or extension
            // changes, making it a *combined* indicator rather than standalone.
            if (alert == null
                && stats.WriteTimestamps.Count >= MassWriteThreshold
                && !stats.AlertedHeuristics.Contains("MassWrite"))
            {
                bool hasExtChanges = stats.ExtensionChangeTimestamps.Count >= ExtensionChangeThreshold / 2;
                bool hasBulkRenames = stats.RenameTimestamps.Count >= BulkRenameThreshold / 2;

                if (hasExtChanges || hasBulkRenames)
                {
                    AttributeProcess(stats);
                    bool wl3; lock (_lock) { wl3 = _whitelist.Contains(stats.ProcessName); }
                    if (!wl3)
                        alert = CreateAlert(stats, "MassWrite",
                            $"Mass write + rename activity — {stats.WriteTimestamps.Count} writes, {stats.RenameTimestamps.Count} renames in {AnalysisWindow.TotalSeconds}s in {stats.DirectoryPath}");
                }
            }

            if (alert != null)
            {
                alerts.Add(alert);
                _alertCooldowns[dirKey] = DateTime.UtcNow;
            }
            else if (!string.IsNullOrEmpty(stats.ProcessName))
            {
                // If the attributed process is whitelisted and no alert fired,
                // clear the cached name so the next analysis tick re-attributes.
                // This prevents a whitelisted name from being permanently stuck
                // to a directory that may later be active under a different process.
                bool cached; lock (_lock) { cached = _whitelist.Contains(stats.ProcessName); }
                if (cached) stats.ProcessName = "";
            }
        }

        // ── Global heuristic: multi-drive simultaneous write ─────────────────
        // Only fires when writes are seen on 3+ distinct drives within the window.
        // Systems with many mapped/network drives commonly touch 2 drives; going
        // to 3+ in a short window is unusual outside of ransomware worm behaviour.
        var recentDrives = _globalDriveAccess
            .Where(kv => DateTime.UtcNow - kv.Value < MultiDriveWindow)
            .Select(kv => kv.Key)
            .ToList();

        if (recentDrives.Count >= MultiDriveThreshold)
        {
            const string cooldownKey = "global_multidrive";
            if (!_alertCooldowns.TryGetValue(cooldownKey, out var lastMultiDrive)
                || DateTime.UtcNow - lastMultiDrive >= CooldownPeriod)
            {
                var (procName, procId, procPath) = ProcessHelper.FindHighIOProcess();
                if (string.IsNullOrEmpty(procName)) procName = "Unknown Process";

                bool whitelisted;
                lock (_lock) { whitelisted = _whitelist.Contains(procName); }

                if (!whitelisted)
                {
                    var driveList = string.Join(", ", recentDrives.Select(d => $"{d}:\\"));
                    alerts.Add(new SuspiciousActivityEventArgs
                    {
                        ProcessName   = procName,
                        ProcessId     = procId,
                        ProcessPath   = procPath,
                        Description   = $"Multi-drive write activity — {recentDrives.Count} drives accessed: {driveList}",
                        HeuristicName = "MultiDrive",
                        DetectedAt    = DateTime.Now
                    });
                    _alertCooldowns[cooldownKey] = DateTime.UtcNow;
                }
            }
        }

        return alerts;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns true if the extension-change pattern looks like encryption:
    ///   - At least one consistent new extension that is not known-benign.
    ///   - Not too many *different* new extensions (IDE/compiler scatter).
    ///   - Not all changes are known-benign pairs (browser downloads, Office saves).
    /// </summary>
    private static bool IsExtensionChangePatternSuspicious(DirectoryStats stats)
    {
        // If the new-extension set is very varied, it is tool/IDE activity, not ransomware
        if (stats.UniqueExtensionsNew.Count > MaxNewExtensionVariants)
            return false;

        // Check how many of the change pairs are known-benign
        int benignCount  = stats.ExtensionChanges.Count(c => IsBenignExtensionChange(c));
        int totalChanges = stats.ExtensionChanges.Count;

        // If more than half the changes are benign pairs, suppress
        if (totalChanges > 0 && benignCount * 2 >= totalChanges)
            return false;

        // If ALL new extensions are in the benign-extensions set, suppress
        bool allNewExtsBenign = stats.UniqueExtensionsNew.Count > 0
            && stats.UniqueExtensionsNew.All(e => BenignNewExtensions.Contains(e));
        if (allNewExtsBenign)
            return false;

        return true;
    }

    private static bool IsBenignExtensionChange(string change)
    {
        // Exact match
        if (BenignExtensionChanges.Contains(change)) return true;

        // Suffix pattern: anything → .tmp / .bak / .part etc.
        var arrowIdx = change.IndexOf('→');
        if (arrowIdx >= 0)
        {
            var newExt = change[(arrowIdx + 1)..];
            if (BenignNewExtensions.Contains(newExt)) return true;
        }

        return false;
    }

    /// <summary>
    /// Try to attribute directory activity to a specific process.
    /// Called on-demand when a threshold is about to fire.
    /// </summary>
    private void AttributeProcess(DirectoryStats stats)
    {
        if (!string.IsNullOrEmpty(stats.ProcessName)) return;

        var (name1, pid1, path1) = ProcessHelper.TryGetLockingProcess(stats.LastTriggerFile);
        if (!string.IsNullOrEmpty(name1))
        {
            stats.ProcessName = name1; stats.ProcessId = pid1; stats.ProcessPath = path1;
            return;
        }

        var (name2, pid2, path2) = ProcessHelper.FindHighIOProcess();
        if (!string.IsNullOrEmpty(name2))
        {
            stats.ProcessName = name2; stats.ProcessId = pid2; stats.ProcessPath = path2;
            return;
        }

        var (name3, pid3, path3) = ProcessHelper.GuessActiveProcess(stats.DirectoryPath);
        if (!string.IsNullOrEmpty(name3))
        {
            stats.ProcessName = name3; stats.ProcessId = pid3; stats.ProcessPath = path3;
            return;
        }

        stats.ProcessName = "Unknown Process";
    }

    private static string GetMostCommonExtChange(List<string> changes)
    {
        if (changes.Count == 0) return "various";
        return changes.GroupBy(c => c)
            .OrderByDescending(g => g.Count())
            .First().Key;
    }

    private static SuspiciousActivityEventArgs CreateAlert(
        DirectoryStats stats, string heuristic, string description)
    {
        stats.AlertedHeuristics.Add(heuristic);
        return new SuspiciousActivityEventArgs
        {
            ProcessName   = stats.ProcessName,
            ProcessId     = stats.ProcessId,
            ProcessPath   = stats.ProcessPath,
            Description   = description,
            TriggerFile   = stats.LastTriggerFile,
            HeuristicName = heuristic,
            DetectedAt    = DateTime.Now
        };
    }
}
