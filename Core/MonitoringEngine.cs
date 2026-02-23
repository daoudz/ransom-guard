using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Diagnostics;

namespace RansomGuard.Core;

/// <summary>
/// Event args for suspicious activity alerts.
/// </summary>
public sealed class SuspiciousActivityEventArgs : EventArgs
{
    public string ProcessName { get; init; } = "Unknown";
    public int ProcessId { get; init; }
    public string ProcessPath { get; init; } = "";
    public string Description { get; init; } = "";
    public string TriggerFile { get; init; } = "";
    public string HeuristicName { get; init; } = "";
    public DateTime DetectedAt { get; init; } = DateTime.Now;
    public string ActionTaken { get; set; } = "Pending";
}

/// <summary>
/// Represents a logged file event for the dashboard live feed.
/// </summary>
public sealed class FileEventLogEntry
{
    public DateTime Timestamp { get; init; }
    public string FilePath { get; init; } = "";
    public string EventType { get; init; } = "";
    public string Details { get; init; } = "";
}

/// <summary>
/// Core monitoring engine. Watches all available drives with FileSystemWatcher
/// and feeds events into the ActivityTracker for heuristic analysis.
/// </summary>
public sealed class MonitoringEngine : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ActivityTracker _tracker;
    private System.Threading.Timer? _analysisTimer;
    private readonly HoneypotManager _honeypot;
    private bool _disposed;

    // Dashboard stats
    private long _totalEventsProcessed;
    private long _eventsThisTick;
    private double _eventsPerSecond;
    private readonly ConcurrentQueue<FileEventLogEntry> _recentEvents = new();
    private readonly List<SuspiciousActivityEventArgs> _alertHistory = new();
    private readonly object _historyLock = new();
    private const int MaxRecentEvents = 500;
    private DateTime _startTime = DateTime.Now;

    // User-defined ignore paths
    private readonly HashSet<string> _ignorePaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _ignorePathsLock = new();

    public event EventHandler<SuspiciousActivityEventArgs>? SuspiciousActivityDetected;
    public bool IsRunning { get; private set; }
    public int WatchedDriveCount => _watchers.Count;
    public long TotalEventsProcessed => _totalEventsProcessed;
    public double EventsPerSecond => _eventsPerSecond;
    public TimeSpan Uptime => DateTime.Now - _startTime;

    public MonitoringEngine()
    {
        _tracker = new ActivityTracker();
        _honeypot = new HoneypotManager();

        // Seed built-in trusted processes so they are never flagged
        foreach (var proc in TrustedProcessList.Entries)
            _tracker.Whitelist(proc);
    }

    /// <summary>Get recent file events for the dashboard live feed.</summary>
    public List<FileEventLogEntry> GetRecentEvents(int count = 100)
    {
        return _recentEvents.TakeLast(count).Reverse().ToList();
    }

    /// <summary>Get alert history for the dashboard threat log.</summary>
    public List<SuspiciousActivityEventArgs> GetAlertHistory()
    {
        lock (_historyLock) { return new List<SuspiciousActivityEventArgs>(_alertHistory); }
    }

    /// <summary>Record an alert into history (called from MainContext).</summary>
    public void RecordAlert(SuspiciousActivityEventArgs alert)
    {
        lock (_historyLock) { _alertHistory.Add(alert); }
    }

    /// <summary>Get live activity stats per directory for dashboard.</summary>
    public Dictionary<string, int> GetActiveDirectories() => _tracker.GetActiveDirectories();

    // ---- Whitelist management ----
    public List<string> GetWhitelist() => _tracker.GetWhitelist();
    public void RemoveFromWhitelist(string procName) => _tracker.RemoveFromWhitelist(procName);

    // ---- Ignore paths management ----
    public void AddIgnorePath(string path)
    {
        lock (_ignorePathsLock) { _ignorePaths.Add(path.TrimEnd('\\', '/')); }
    }

    public void RemoveIgnorePath(string path)
    {
        lock (_ignorePathsLock) { _ignorePaths.Remove(path.TrimEnd('\\', '/')); }
    }

    public List<string> GetIgnorePaths()
    {
        lock (_ignorePathsLock) { return new List<string>(_ignorePaths); }
    }

    public void Start()
    {
        if (IsRunning) return;

        _startTime = DateTime.Now;
        _totalEventsProcessed = 0;

        // Deploy honeypot files
        _honeypot.Deploy();

        // Create watchers for each ready drive
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable)
            .ToList();

        foreach (var drive in drives)
        {
            try
            {
                var watcher = CreateWatcher(drive.RootDirectory.FullName);
                _watchers.Add(watcher);
                watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[MonitoringEngine] Failed to watch {drive.Name}: {ex.Message}");
            }
        }

        // Periodic analysis every 2 seconds
        _analysisTimer = new System.Threading.Timer(
            AnalyzeTick, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));

        IsRunning = true;
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _analysisTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        _analysisTimer?.Dispose();
        _analysisTimer = null;

        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();

        _tracker.Clear();
        IsRunning = false;
    }

    public void WhitelistProcess(string processName)
    {
        _tracker.Whitelist(processName);
    }

    private FileSystemWatcher CreateWatcher(string path)
    {
        var watcher = new FileSystemWatcher(path)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName
                         | NotifyFilters.LastWrite
                         | NotifyFilters.Size
                         | NotifyFilters.DirectoryName,
            Filter = "*.*",
            InternalBufferSize = 65536 // 64KB buffer for high-volume scenarios
        };

        watcher.Created += OnFileEvent;
        watcher.Changed += OnFileEvent;
        watcher.Deleted += OnFileEvent;
        watcher.Renamed += OnFileRenamed;
        watcher.Error += OnWatcherError;

        return watcher;
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (!IsRunning) return;

        // Skip our own honeypot management
        if (HoneypotManager.IsHoneypotPath(e.FullPath)) return;

        // Skip only true system noise (NOT user temp — ransomware targets temp too)
        if (IsSystemNoise(e.FullPath)) return;

        // Skip user-defined ignore paths
        if (IsUserIgnored(e.FullPath)) return;

        Interlocked.Increment(ref _totalEventsProcessed);
        Interlocked.Increment(ref _eventsThisTick);

        var driveLetter = Path.GetPathRoot(e.FullPath)?[0] ?? '?';

        // Log for dashboard
        EnqueueEvent(new FileEventLogEntry
        {
            Timestamp = DateTime.Now,
            FilePath = e.FullPath,
            EventType = e.ChangeType.ToString(),
            Details = e.ChangeType == WatcherChangeTypes.Deleted ? "File deleted" : "File modified/created"
        });

        _tracker.RecordEvent(new FileActivityEvent
        {
            FilePath = e.FullPath,
            ChangeType = e.ChangeType,
            DriveLetter = driveLetter,
            Timestamp = DateTime.UtcNow
        });

        // Check honeypot immediately
        if (_honeypot.IsHoneypotFile(e.FullPath))
        {
            var alert = _tracker.CreateHoneypotAlert(e.FullPath);
            if (alert != null)
            {
                RecordAlert(alert);
                SuspiciousActivityDetected?.Invoke(this, alert);
            }
        }
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        if (!IsRunning) return;
        if (HoneypotManager.IsHoneypotPath(e.FullPath)) return;
        if (IsSystemNoise(e.FullPath)) return;
        if (IsUserIgnored(e.FullPath)) return;

        Interlocked.Increment(ref _totalEventsProcessed);
        Interlocked.Increment(ref _eventsThisTick);

        var driveLetter = Path.GetPathRoot(e.FullPath)?[0] ?? '?';
        var oldExt = Path.GetExtension(e.OldName)?.ToLowerInvariant() ?? "";
        var newExt = Path.GetExtension(e.Name)?.ToLowerInvariant() ?? "";
        var isExtChange = oldExt != newExt && !string.IsNullOrEmpty(oldExt) && !string.IsNullOrEmpty(newExt);

        // Log for dashboard
        EnqueueEvent(new FileEventLogEntry
        {
            Timestamp = DateTime.Now,
            FilePath = e.FullPath,
            EventType = isExtChange ? "ExtChange" : "Renamed",
            Details = isExtChange
                ? $"{oldExt} → {newExt}"
                : $"From: {Path.GetFileName(e.OldName)}"
        });

        _tracker.RecordEvent(new FileActivityEvent
        {
            FilePath = e.FullPath,
            OldPath = e.OldFullPath,
            ChangeType = WatcherChangeTypes.Renamed,
            DriveLetter = driveLetter,
            OldExtension = oldExt,
            NewExtension = newExt,
            IsExtensionChange = isExtChange,
            Timestamp = DateTime.UtcNow
        });

        // Check honeypot
        if (_honeypot.IsHoneypotFile(e.OldFullPath))
        {
            var alert = _tracker.CreateHoneypotAlert(e.OldFullPath);
            if (alert != null)
            {
                RecordAlert(alert);
                SuspiciousActivityDetected?.Invoke(this, alert);
            }
        }
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        Debug.WriteLine($"[MonitoringEngine] Watcher error: {e.GetException()?.Message}");
    }

    private void AnalyzeTick(object? state)
    {
        if (!IsRunning) return;

        // Update events/sec
        var tick = Interlocked.Exchange(ref _eventsThisTick, 0);
        _eventsPerSecond = tick / 2.0; // Timer fires every 2s

        try
        {
            var alerts = _tracker.Analyze();
            foreach (var alert in alerts)
            {
                RecordAlert(alert);
                SuspiciousActivityDetected?.Invoke(this, alert);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[MonitoringEngine] Analysis error: {ex.Message}");
        }
    }

    private void EnqueueEvent(FileEventLogEntry entry)
    {
        _recentEvents.Enqueue(entry);
        // Trim to max size
        while (_recentEvents.Count > MaxRecentEvents)
            _recentEvents.TryDequeue(out _);
    }

    /// <summary>
    /// Filter genuine OS noise AND well-known high-volume benign I/O paths.
    ///
    /// Ransomware and malware frequently operate in USER temp directories, so we
    /// do NOT filter those. We only suppress paths that exclusively produce benign
    /// noise at scale: browser caches, AV working dirs, package caches, IDE output.
    /// </summary>
    private static bool IsSystemNoise(string path)
    {
        var lower = path.ToLowerInvariant();

        // ── Core Windows OS noise ─────────────────────────────────────────────
        if (lower.Contains(@"\$recycle.bin")) return true;
        if (lower.Contains(@"\system volume information")) return true;
        if (lower.Contains(@"\windows\temp")) return true;
        if (lower.Contains(@"\windows\prefetch")) return true;
        if (lower.Contains(@"\windows\servicing")) return true;
        if (lower.Contains(@"\windows\softwaredistribution")) return true;
        if (lower.Contains(@"\windows\winsxs")) return true;
        if (lower.EndsWith("~")) return true;

        // ── Browser profile directories (suppress entire tree) ────────────────
        // ALL writes under User Data / Firefox Profiles are browser-managed.
        // Using a blanket match so Profile 1, Profile 2, temp, cache, extensions,
        // sync data, trusted_vault, etc. are ALL covered without listing each one.
        if (lower.Contains(@"\google\chrome\user data\")) return true;
        if (lower.Contains(@"\microsoft\edge\user data\")) return true;
        if (lower.Contains(@"\chromium\user data\")) return true;
        if (lower.Contains(@"\brave-browser\user data\")) return true;
        if (lower.Contains(@"\opera software\opera stable\")) return true;
        if (lower.Contains(@"\opera software\opera gx stable\")) return true;
        if (lower.Contains(@"\vivaldi\user data\")) return true;
        if (lower.Contains(@"\mozilla\firefox\profiles\")) return true;
        // Generic browser download temp files
        if (lower.EndsWith(".crdownload") || lower.EndsWith(".part") || lower.EndsWith(".download")) return true;

        // ── Antivirus / Windows Defender working dirs ─────────────────────────
        if (lower.Contains(@"\windows defender\")) return true;
        if (lower.Contains(@"\microsoft\windows defender\")) return true;
        if (lower.Contains(@"\windowsdefender\")) return true;
        if (lower.Contains(@"\programdata\microsoft\windows defender")) return true;
        // Common AV quarantine / scan cache paths
        if (lower.Contains(@"\quarantine\")) return true;
        if (lower.Contains(@"\avcache\")) return true;

        // ── Package manager caches ────────────────────────────────────────────
        if (lower.Contains(@"\node_modules\")) return true;
        if (lower.Contains(@"\npm-cache\")) return true;
        if (lower.Contains(@"\appdata\roaming\npm\")) return true;
        if (lower.Contains(@"\pip\cache\")) return true;
        if (lower.Contains(@"\nuget\packages\")) return true;
        if (lower.Contains(@"\.nuget\")) return true;
        if (lower.Contains(@"\.cargo\registry\")) return true;
        if (lower.Contains(@"\go\pkg\mod\")) return true;

        // ── IDE / build output ────────────────────────────────────────────────
        if (lower.Contains(@"\.vs\")) return true;
        if (lower.Contains(@"\.idea\")) return true;
        if (lower.Contains(@"\.git\objects")) return true;
        if (lower.Contains(@"\obj\debug\")) return true;
        if (lower.Contains(@"\obj\release\")) return true;
        if (lower.Contains(@"\bin\debug\")) return true;
        if (lower.Contains(@"\bin\release\")) return true;
        if (lower.Contains(@"\.next\cache")) return true;  // Next.js
        if (lower.Contains(@"\__pycache__\")) return true;

        // ── Microsoft Teams & auto-updaters ───────────────────────────────────
        if (lower.Contains(@"\appdata\local\microsoft\teams\")) return true;
        if (lower.Contains(@"\appdata\local\microsoft\teamsmeetingaddin\")) return true;
        if (lower.Contains(@"\squirrel.com\")) return true;          // Squirrel updater (Teams, Slack, etc.)
        if (lower.Contains(@"\appdata\local\slack\")) return true;
        if (lower.Contains(@"\appdata\local\discord\")) return true;
        if (lower.Contains(@"\appdata\local\spotify\")) return true;


        // ── Windows Update / WinGet ───────────────────────────────────────────
        if (lower.Contains(@"\appdata\local\temp\winget\")) return true;
        if (lower.Contains(@"\appdata\local\packages\microsoft.winget")) return true;

        // ── Cloud sync / OneDrive temp ────────────────────────────────────────
        if (lower.Contains(@"\onedrive\") && lower.Contains(@"\.lock")) return true;
        if (lower.Contains(@"\.tmp") && lower.Contains(@"\onedrive\")) return true;

        // ── Windows Search / indexer ──────────────────────────────────────────
        if (lower.Contains(@"\microsoft\search\")) return true;
        if (lower.Contains(@"\windows\system32\config\journal")) return true;

        return false;
    }

    /// <summary>
    /// Check if the path matches any user-defined ignore paths.
    /// </summary>
    private bool IsUserIgnored(string path)
    {
        lock (_ignorePathsLock)
        {
            foreach (var ignorePath in _ignorePaths)
            {
                if (path.StartsWith(ignorePath, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _honeypot.Cleanup();
    }
}
