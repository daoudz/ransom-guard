using System;
using System.IO;
using System.Threading;

namespace RansomSim;

/// <summary>
/// SAFE Ransomware Simulator — for testing RansomGuard ONLY.
/// 
/// This program simulates ransomware-like behavior using ONLY temporary files
/// it creates itself. It does NOT touch any real user files.
/// 
/// Behaviors simulated:
///   1. Bulk file creation (mass write)
///   2. Bulk file rename with extension changes (.docx → .encrypted)
///   3. Honeypot file access (touches RansomGuard bait files)
///   4. Rapid sequential file operations
/// </summary>
class Program
{
    static readonly string SimDir = Path.Combine(Path.GetTempPath(), "RansomSim_Test");

    static void Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║     🧪 RansomSim — Safe Ransomware Simulator        ║");
        Console.WriteLine("║     For testing RansomGuard detection ONLY           ║");
        Console.WriteLine("║     NO real files will be harmed.                    ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();

        Console.WriteLine("This tool simulates ransomware-like activity to trigger");
        Console.WriteLine("RansomGuard's detection heuristics. All operations use");
        Console.WriteLine($"temporary files in: {SimDir}");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("Make sure RansomGuard is running before starting!");
        Console.ResetColor();
        Console.WriteLine();

        Console.WriteLine("Available tests:");
        Console.WriteLine("  [1] Mass File Write       — Creates 60+ files rapidly");
        Console.WriteLine("  [2] Bulk Rename           — Renames 20+ files rapidly");
        Console.WriteLine("  [3] Extension Change      — Changes extensions (.docx → .encrypted)");
        Console.WriteLine("  [4] Honeypot Touch        — Tries to access honeypot bait files");
        Console.WriteLine("  [5] Full Simulation       — Runs ALL tests in sequence");
        Console.WriteLine("  [0] Exit");
        Console.WriteLine();

        while (true)
        {
            Console.Write("Select test [0-5]: ");
            var key = Console.ReadKey();
            Console.WriteLine();

            switch (key.KeyChar)
            {
                case '1': RunMassWrite(); break;
                case '2': RunBulkRename(); break;
                case '3': RunExtensionChange(); break;
                case '4': RunHoneypotTouch(); break;
                case '5': RunFullSimulation(); break;
                case '0':
                    Cleanup();
                    Console.WriteLine("Goodbye!");
                    return;
                default:
                    Console.WriteLine("Invalid option. Try 0-5.");
                    break;
            }

            Console.WriteLine();
        }
    }

    /// <summary>
    /// Test 1: Mass File Write — triggers the MassWrite heuristic (≥50 writes in 5s).
    /// </summary>
    static void RunMassWrite()
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n▶ TEST 1: Mass File Write");
        Console.WriteLine("  Creating 60 files as fast as possible...");
        Console.ResetColor();

        EnsureDir();

        for (int i = 1; i <= 60; i++)
        {
            var filePath = Path.Combine(SimDir, $"document_{i:D3}.docx");
            File.WriteAllText(filePath, $"Simulated document content #{i}. " +
                $"This file was created by RansomSim for testing purposes at {DateTime.Now}. " +
                $"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor.");

            if (i % 10 == 0)
                Console.WriteLine($"  Created {i}/60 files...");
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✅ Done! RansomGuard should detect 'Mass File Write' activity.");
        Console.ResetColor();

        WaitForDetection();
    }

    /// <summary>
    /// Test 2: Bulk Rename — triggers the BulkRename heuristic (≥15 renames in 5s).
    /// </summary>
    static void RunBulkRename()
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n▶ TEST 2: Bulk File Rename");
        Console.WriteLine("  Creating and rapidly renaming 25 files...");
        Console.ResetColor();

        EnsureDir();

        // First create the files
        for (int i = 1; i <= 25; i++)
        {
            var filePath = Path.Combine(SimDir, $"report_{i:D3}.pdf");
            File.WriteAllText(filePath, $"Simulated report #{i}");
        }

        Thread.Sleep(500); // Small pause before the burst

        // Now rename them all rapidly
        for (int i = 1; i <= 25; i++)
        {
            var oldPath = Path.Combine(SimDir, $"report_{i:D3}.pdf");
            var newPath = Path.Combine(SimDir, $"renamed_report_{i:D3}.pdf");
            if (File.Exists(oldPath))
                File.Move(oldPath, newPath);

            if (i % 5 == 0)
                Console.WriteLine($"  Renamed {i}/25 files...");
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✅ Done! RansomGuard should detect 'Bulk Rename' activity.");
        Console.ResetColor();

        WaitForDetection();
    }

    /// <summary>
    /// Test 3: Extension Change — triggers the ExtensionChange heuristic (≥10 in 5s).
    /// This is the most common ransomware behavior: changing .docx to .encrypted, .locked, etc.
    /// </summary>
    static void RunExtensionChange()
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n▶ TEST 3: Extension Change (Encryption Simulation)");
        Console.WriteLine("  Creating files and changing extensions to .encrypted...");
        Console.ResetColor();

        EnsureDir();

        var extensions = new[] { ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".png", ".txt", ".csv" };

        // Create files with normal extensions
        for (int i = 1; i <= 20; i++)
        {
            var ext = extensions[(i - 1) % extensions.Length];
            var filePath = Path.Combine(SimDir, $"important_file_{i:D3}{ext}");
            File.WriteAllText(filePath, $"Important data #{i} - Original content before 'encryption'");
        }

        Thread.Sleep(500);

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ⚡ Now 'encrypting' files (changing extensions)...");
        Console.ResetColor();

        // Rapidly change all extensions to .encrypted
        for (int i = 1; i <= 20; i++)
        {
            var ext = extensions[(i - 1) % extensions.Length];
            var oldPath = Path.Combine(SimDir, $"important_file_{i:D3}{ext}");
            var newPath = Path.Combine(SimDir, $"important_file_{i:D3}.encrypted");

            if (File.Exists(oldPath))
            {
                // Overwrite content to simulate encryption
                File.WriteAllText(oldPath, Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes(File.ReadAllText(oldPath))));
                File.Move(oldPath, newPath);
            }

            if (i % 5 == 0)
                Console.WriteLine($"  'Encrypted' {i}/20 files...");
        }

        // Create a "ransom note" (harmless text file)
        var ransomNotePath = Path.Combine(SimDir, "README_DECRYPT.txt");
        File.WriteAllText(ransomNotePath,
            "=== THIS IS A TEST ===\n" +
            "This is a simulated ransom note created by RansomSim.\n" +
            "No real files were harmed.\n" +
            "=== THIS IS A TEST ===");
        Console.WriteLine("  📝 Dropped simulated ransom note: README_DECRYPT.txt");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  ✅ Done! RansomGuard should detect 'Extension Change' activity.");
        Console.ResetColor();

        WaitForDetection();
    }

    /// <summary>
    /// Test 4: Honeypot Touch — attempts to modify RansomGuard's bait files.
    /// </summary>
    static void RunHoneypotTouch()
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("\n▶ TEST 4: Honeypot File Access");
        Console.WriteLine("  Looking for RansomGuard honeypot bait files...");
        Console.ResetColor();

        bool found = false;

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady || drive.DriveType != DriveType.Fixed) continue;

            var honeypotDir = Path.Combine(drive.RootDirectory.FullName, ".RG_Protected");
            if (!Directory.Exists(honeypotDir))
            {
                Console.WriteLine($"  No honeypot directory on {drive.Name}");
                continue;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  Found honeypot directory: {honeypotDir}");
            Console.ResetColor();

            var files = Directory.GetFiles(honeypotDir);
            foreach (var file in files)
            {
                if (Path.GetFileName(file).StartsWith(".")) continue; // Skip marker

                try
                {
                    Console.WriteLine($"  Attempting to read: {Path.GetFileName(file)}");
                    // Try to read the file (this should trigger the alert)
                    var content = File.ReadAllText(file);
                    // Try to write back (modify)
                    File.SetAttributes(file, FileAttributes.Normal);
                    File.AppendAllText(file, "\n[SIMULATED MODIFICATION BY RANSOMSIM]");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  ⚡ Modified honeypot file: {Path.GetFileName(file)}");
                    Console.ResetColor();
                    found = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Could not access {Path.GetFileName(file)}: {ex.Message}");
                }
            }
        }

        if (found)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✅ Done! RansomGuard should detect 'Honeypot' trigger.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  ⚠ No honeypot files found. Make sure RansomGuard is running first.");
        }
        Console.ResetColor();

        WaitForDetection();
    }

    /// <summary>
    /// Test 5: Full Simulation — runs all tests in sequence with pauses between them.
    /// </summary>
    static void RunFullSimulation()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\n╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║          🔥 FULL RANSOMWARE SIMULATION 🔥           ║");
        Console.WriteLine("║          Running all tests in sequence...            ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();

        Console.WriteLine("\n--- Phase 1 of 4: Mass File Write ---");
        RunMassWrite();

        Console.WriteLine("\n⏳ Waiting 3 seconds before next phase...");
        Thread.Sleep(3000);

        Console.WriteLine("\n--- Phase 2 of 4: Bulk Rename ---");
        RunBulkRename();

        Console.WriteLine("\n⏳ Waiting 3 seconds before next phase...");
        Thread.Sleep(3000);

        Console.WriteLine("\n--- Phase 3 of 4: Extension Change (Encryption) ---");
        RunExtensionChange();

        Console.WriteLine("\n⏳ Waiting 3 seconds before next phase...");
        Thread.Sleep(3000);

        Console.WriteLine("\n--- Phase 4 of 4: Honeypot Access ---");
        RunHoneypotTouch();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║         ✅ FULL SIMULATION COMPLETE                  ║");
        Console.WriteLine("║         Check RansomGuard for alerts!                ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();
    }

    static void EnsureDir()
    {
        if (Directory.Exists(SimDir))
        {
            // Clean previous test files
            try { Directory.Delete(SimDir, true); }
            catch { }
        }
        Directory.CreateDirectory(SimDir);
    }

    static void Cleanup()
    {
        Console.WriteLine("Cleaning up test files...");
        try
        {
            if (Directory.Exists(SimDir))
                Directory.Delete(SimDir, true);
            Console.WriteLine("  ✅ Test files cleaned up.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ⚠ Cleanup error: {ex.Message}");
        }
    }

    static void WaitForDetection()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  (Waiting 5 seconds for RansomGuard to analyze...)");
        Console.ResetColor();
        Thread.Sleep(5000);
    }
}
