using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace RansomGuard.Core;

/// <summary>
/// Manages honeypot bait files that trigger immediate alerts when modified.
/// </summary>
public sealed class HoneypotManager
{
    private const string HoneypotMarker = ".ransomguard_honeypot";
    private const string HoneypotDirName = ".RG_Protected";
    private readonly HashSet<string> _honeypotFiles = new(StringComparer.OrdinalIgnoreCase);

    // Bait file templates — common document types targeted by ransomware
    private static readonly (string Name, string Content)[] BaitFiles = new[]
    {
        ("Important_Documents.docx", "This is a protected bait file. Do not modify."),
        ("Financial_Records.xlsx", "This is a protected bait file. Do not modify."),
        ("Company_Report.pdf", "This is a protected bait file. Do not modify."),
        ("Backup_Archive.zip", "This is a protected bait file. Do not modify."),
        ("Project_Notes.txt", "This is a protected bait file. Do not modify."),
    };

    /// <summary>Deploy honeypot bait files on each fixed drive.</summary>
    public void Deploy()
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .ToList();

        foreach (var drive in drives)
        {
            try
            {
                var honeypotDir = Path.Combine(drive.RootDirectory.FullName, HoneypotDirName);
                if (!Directory.Exists(honeypotDir))
                {
                    var dirInfo = Directory.CreateDirectory(honeypotDir);
                    dirInfo.Attributes |= FileAttributes.Hidden;
                }

                // Create marker file
                var markerPath = Path.Combine(honeypotDir, HoneypotMarker);
                if (!File.Exists(markerPath))
                    File.WriteAllText(markerPath, "RansomGuard Honeypot Directory");
                File.SetAttributes(markerPath, FileAttributes.Hidden | FileAttributes.System);

                foreach (var (name, content) in BaitFiles)
                {
                    var filePath = Path.Combine(honeypotDir, name);
                    if (!File.Exists(filePath))
                    {
                        File.WriteAllText(filePath, content);
                        // Set to read-only (ransomware often ignores this)
                        File.SetAttributes(filePath, FileAttributes.ReadOnly);
                    }
                    _honeypotFiles.Add(filePath);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HoneypotManager] Failed to deploy on {drive.Name}: {ex.Message}");
            }
        }
    }

    /// <summary>Remove all honeypot bait files.</summary>
    public void Cleanup()
    {
        foreach (var file in _honeypotFiles)
        {
            try
            {
                if (File.Exists(file))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                    File.Delete(file);
                }
            }
            catch { }
        }
        _honeypotFiles.Clear();
    }

    /// <summary>Check if a file path is one of our honeypot bait files.</summary>
    public bool IsHoneypotFile(string path)
    {
        return _honeypotFiles.Contains(path);
    }

    /// <summary>Check if a path is within a honeypot directory (used to skip monitoring noise).</summary>
    public static bool IsHoneypotPath(string path)
    {
        return path.Contains(HoneypotDirName, StringComparison.OrdinalIgnoreCase);
    }
}
