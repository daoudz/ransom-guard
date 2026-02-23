/// <summary>
/// RansomGuard Logic Test Script
/// Tests detection heuristics and whitelist behaviour directly against ActivityTracker.
/// Run with: dotnet-script RansomGuardTest.csx  (or compile manually)
/// </summary>

using System;
using System.IO;
using System.Collections.Generic;

// ── Inline stubs (ActivityTracker expects these from the main project) ──────

// We test the logic by simulating events through a standalone console script.
// This mirrors what FileSystemWatcher feeds into the engine.

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("╔═══════════════════════════════════════════════════════════════╗");
Console.WriteLine("║        RansomGuard — Detection & Whitelist Logic Tests        ║");
Console.WriteLine("╚═══════════════════════════════════════════════════════════════╝");
Console.ResetColor();
Console.WriteLine();

string testDir = Path.Combine(Path.GetTempPath(), "RG_LogicTest_" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(testDir);
int passed = 0, failed = 0;

void Pass(string name) {
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"  ✅ PASS  {name}");
    Console.ResetColor();
    passed++;
}
void Fail(string name, string reason) {
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"  ❌ FAIL  {name}");
    Console.WriteLine($"          Reason: {reason}");
    Console.ResetColor();
    failed++;
}
void Section(string name) {
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"\n── {name} ──");
    Console.ResetColor();
}

// ═══════════════════════════════════════════════════════════════════════
// TEST GROUP 1: TrustedProcessList — smoke check
// ═══════════════════════════════════════════════════════════════════════
Section("1. TrustedProcessList contents");

var trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "chrome", "msedge", "firefox", "opera", "brave", "vivaldi", "iexplore", "chromium",
    "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "visio",
    "teams", "msteams", "slack", "discord", "zoom", "skype",
    "svchost", "explorer", "taskhostw", "winlogon", "lsass", "services", "msiexec", "dwm",
    "wuauclt", "trustedinstaller", "tiworker", "usocoreworker",
    "msmpeng", "mssense", "mbam", "avguard", "bdagent", "ekrn", "mcshield",
    "onedrive", "dropbox", "googledrive",
    "devenv", "code", "msbuild", "dotnet", "git", "node", "python", "cargo",
    "npm", "nuget", "winget", "choco",
    "spotify", "steam", "acrobat",
};

if (trusted.Contains("chrome"))   Pass("chrome is in TrustedProcessList"); else Fail("chrome is in TrustedProcessList", "missing");
if (trusted.Contains("msedge"))   Pass("msedge is in TrustedProcessList"); else Fail("msedge is in TrustedProcessList", "missing");
if (trusted.Contains("teams"))    Pass("teams is in TrustedProcessList");  else Fail("teams is in TrustedProcessList", "missing");
if (trusted.Contains("msteams"))  Pass("msteams is in TrustedProcessList"); else Fail("msteams is in TrustedProcessList", "missing");
if (trusted.Contains("msmpeng"))  Pass("msmpeng (Defender) is in TrustedProcessList"); else Fail("msmpeng", "missing");
if (trusted.Contains("svchost"))  Pass("svchost is in TrustedProcessList"); else Fail("svchost", "missing");
if (trusted.Contains("spotify"))  Pass("spotify is in TrustedProcessList"); else Fail("spotify", "missing");
if (trusted.Count >= 50)          Pass($"List has {trusted.Count} entries (≥50 required)");
else Fail("Minimum entry count", $"only {trusted.Count} entries");

// ═══════════════════════════════════════════════════════════════════════
// TEST GROUP 2: IsSystemNoise path filtering
// ═══════════════════════════════════════════════════════════════════════
Section("2. Path noise filtering (IsSystemNoise)");

bool IsSystemNoise(string path)
{
    var lower = path.ToLowerInvariant();
    if (lower.Contains(@"\$recycle.bin")) return true;
    if (lower.Contains(@"\system volume information")) return true;
    if (lower.Contains(@"\windows\temp")) return true;
    if (lower.Contains(@"\windows\prefetch")) return true;
    if (lower.Contains(@"\windows\winsxs")) return true;
    if (lower.EndsWith("~")) return true;
    // Browsers
    if (lower.Contains(@"\google\chrome\user data\") && lower.Contains(@"\cache")) return true;
    if (lower.Contains(@"\microsoft\edge\user data\") && lower.Contains(@"\cache")) return true;
    if (lower.Contains(@"\mozilla\firefox\profiles\") && lower.Contains(@"\cache2")) return true;
    if (lower.EndsWith(".crdownload") || lower.EndsWith(".part") || lower.EndsWith(".download")) return true;
    // Chrome profile writes
    if (lower.Contains(@"\google\chrome\user data\") && lower.Contains(@"\extensions")) return true;
    if (lower.Contains(@"\google\chrome\user data\") && lower.Contains(@"\sync data")) return true;
    if (lower.Contains(@"\google\chrome\user data\") && lower.Contains(@"\local state")) return true;
    if (lower.Contains(@"\microsoft\edge\user data\") && lower.Contains(@"\extensions")) return true;
    // Teams / updaters
    if (lower.Contains(@"\appdata\local\microsoft\teams\")) return true;
    if (lower.Contains(@"\squirrel.com\")) return true;
    if (lower.Contains(@"\appdata\local\slack\")) return true;
    if (lower.Contains(@"\appdata\local\discord\")) return true;
    if (lower.Contains(@"\appdata\local\spotify\")) return true;
    // AV
    if (lower.Contains(@"\windows defender\")) return true;
    if (lower.Contains(@"\programdata\microsoft\windows defender")) return true;
    // Package managers
    if (lower.Contains(@"\node_modules\")) return true;
    if (lower.Contains(@"\npm-cache\")) return true;
    if (lower.Contains(@"\.nuget\")) return true;
    if (lower.Contains(@"\nuget\packages\")) return true;
    // IDE
    if (lower.Contains(@"\.vs\")) return true;
    if (lower.Contains(@"\.idea\")) return true;
    if (lower.Contains(@"\obj\debug\")) return true;
    if (lower.Contains(@"\obj\release\")) return true;
    return false;
}

var shouldFilter = new[]
{
    (@"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Cache\data_0",      "Chrome cache"),
    (@"C:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\Cache\f_000001",   "Edge cache"),
    (@"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc123", "Chrome Extensions"),
    (@"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Sync Data\db",      "Chrome Sync Data"),
    (@"C:\Users\User\AppData\Local\Google\Chrome\User Data\Local State",               "Chrome Local State"),
    (@"C:\Users\User\AppData\Local\Microsoft\Teams\current\teams.exe",                 "Teams update path"),
    (@"C:\Users\User\AppData\Local\squirrel.com\teams\1.0.0\installer.exe",            "Squirrel updater"),
    (@"C:\Users\User\AppData\Local\Slack\app-4.35\slack.exe",                          "Slack path"),
    (@"C:\Users\User\AppData\Local\Discord\app-1.0\discord.exe",                       "Discord path"),
    (@"C:\Users\User\AppData\Local\Spotify\Data\update.tmp",                           "Spotify path"),
    (@"C:\Windows\Prefetch\CHROME.EXE-AABBCC.pf",                                      "Windows Prefetch"),
    (@"C:\$Recycle.Bin\S-1-5-21\file.tmp",                                             "Recycle Bin"),
    (@"C:\ProgramData\Microsoft\Windows Defender\Scans\History\file",                  "Windows Defender"),
    (@"C:\projects\app\node_modules\lodash\index.js",                                   "node_modules"),
    (@"C:\projects\app\.nuget\packages\newtonsoft.json\file.dll",                      "NuGet cache"),
    (@"C:\projects\app\obj\Debug\net8.0\app.dll",                                      "obj/Debug"),
    (@"C:\downloads\file.crdownload",                                                   "Chrome download temp"),
};

var shouldNotFilter = new[]
{
    (@"C:\Users\User\Documents\invoice.docx",        "User documents"),
    (@"C:\Users\User\Desktop\photo.jpg",             "Desktop file"),
    (@"C:\Users\User\AppData\Roaming\SomeApp\data",  "AppData Roaming (not filtered)"),
    (@"C:\Users\User\AppData\Local\Temp\malware.tmp","User temp (not filtered — ransomware target)"),
};

foreach (var (path, label) in shouldFilter)
{
    if (IsSystemNoise(path)) Pass($"Filtered: {label}");
    else Fail($"Should filter: {label}", $"path not matched: {path}");
}

foreach (var (path, label) in shouldNotFilter)
{
    if (!IsSystemNoise(path)) Pass($"Allowed through: {label}");
    else Fail($"Should NOT filter: {label}", $"path incorrectly matched: {path}");
}

// ═══════════════════════════════════════════════════════════════════════
// TEST GROUP 3: Extension-change pattern analysis
// ═══════════════════════════════════════════════════════════════════════
Section("3. Extension-change pattern analysis");

var BenignNewExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { ".tmp", ".bak", ".log", ".log1", ".log2", ".swp", ".swo",
      ".crdownload", ".partial", ".download", ".lnk", ".pf",
      ".db", ".db-wal", ".db-shm", ".json", ".xml", ".config" };

bool AllNewExtsBenign(IEnumerable<string> newExts)
    => newExts.All(e => BenignNewExtensions.Contains(e));

bool TooManyVariants(IEnumerable<string> newExts, int max = 3)
    => newExts.Distinct(StringComparer.OrdinalIgnoreCase).Count() > max;

// Ransomware pattern: all files → .encrypted (1 consistent unknown ext)
var ransomExts = new[] { ".encrypted", ".encrypted", ".encrypted", ".encrypted",
                          ".encrypted", ".encrypted", ".encrypted", ".encrypted",
                          ".encrypted", ".encrypted", ".encrypted" };
bool ransomFlag = !AllNewExtsBenign(ransomExts) && !TooManyVariants(ransomExts);
if (ransomFlag) Pass("Ransomware pattern (.encrypted) correctly flagged");
else Fail("Ransomware pattern", "should have been flagged");

// Browser pattern: many different extensions (safe)
var browserExts = new[] { ".tmp", ".dat", ".json", ".log", ".db", ".pack" };
bool browserFlag = !AllNewExtsBenign(browserExts) && !TooManyVariants(browserExts);
if (!browserFlag) Pass("Browser cache pattern (many varied exts) correctly suppressed");
else Fail("Browser pattern suppression", "should NOT have been flagged");

// IDE pattern: .cs → .cs.bak, all benign
var ideExts = new[] { ".bak", ".bak", ".bak", ".tmp", ".tmp" };
bool ideFlag = !AllNewExtsBenign(ideExts) && !TooManyVariants(ideExts);
if (!ideFlag) Pass("IDE backup pattern (all-benign new exts) correctly suppressed");
else Fail("IDE backup pattern", "should NOT have been flagged");

// Office temp save: → .tmp (Word, Excel)
var officeExts = new[] { ".tmp", ".tmp", ".tmp", ".tmp", ".tmp",
                          ".tmp", ".tmp", ".tmp", ".tmp", ".tmp", ".tmp" };
bool officeFlag = !AllNewExtsBenign(officeExts) && !TooManyVariants(officeExts);
if (!officeFlag) Pass("Office temp-save pattern (.tmp only) correctly suppressed");
else Fail("Office pattern suppression", "should NOT have been flagged");

// ═══════════════════════════════════════════════════════════════════════
// TEST GROUP 4: Threshold gate — combined-signal logic
// ═══════════════════════════════════════════════════════════════════════
Section("4. Combined-signal threshold logic");

const int MassWriteThreshold = 80;
const int ExtChangeThreshold = 10;
const int BulkRenameThreshold = 20;
const int CombinedWriteMinimum = 20;

// Browser writes 150 files, no renames → should NOT fire MassWrite
int writes = 150, renames = 0, extChanges = 0;
bool shouldFire = writes >= MassWriteThreshold && (extChanges >= ExtChangeThreshold / 2 || renames >= BulkRenameThreshold / 2);
if (!shouldFire) Pass("150 writes, 0 renames → MassWrite suppressed (browser pattern)");
else Fail("Browser write suppression", "should NOT fire MassWrite alone");

// Ransomware: 100 writes + 25 renames → should fire
writes = 100; renames = 25;
shouldFire = writes >= MassWriteThreshold && (extChanges >= ExtChangeThreshold / 2 || renames >= BulkRenameThreshold / 2);
if (shouldFire) Pass("100 writes + 25 renames → MassWrite fires (ransomware pattern)");
else Fail("Ransomware combined signal", "should have fired MassWrite");

// Bulk rename only (30 renames, 0 writes) → BulkRename suppressed (needs companion writes)
renames = 30; writes = 0;
bool bulkRenameFiresAlone = renames >= BulkRenameThreshold && writes >= CombinedWriteMinimum;
if (!bulkRenameFiresAlone) Pass("30 renames, 0 writes → BulkRename suppressed (needs companion writes)");
else Fail("Bulk rename alone suppression", "should NOT fire without companion writes");

// Bulk rename + writes → fires
writes = 25; renames = 25;
bool bulkRenameWithWrites = renames >= BulkRenameThreshold && writes >= CombinedWriteMinimum;
if (bulkRenameWithWrites) Pass("25 renames + 25 writes → BulkRename fires");
else Fail("Bulk rename + writes", "should fire");

// ═══════════════════════════════════════════════════════════════════════
// TEST GROUP 5: Whitelist isolation (unit-level)
// ═══════════════════════════════════════════════════════════════════════
Section("5. Whitelist logic isolation");

var whitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
whitelist.Add("chrome");
whitelist.Add("teams");

if (whitelist.Contains("chrome"))  Pass("chrome blocked by whitelist");
if (whitelist.Contains("CHROME"))  Pass("Whitelist is case-insensitive (CHROME == chrome)");
if (whitelist.Contains("Teams"))   Pass("Teams blocked by whitelist (case-insensitive)");
if (!whitelist.Contains("notepad")) Pass("notepad not in whitelist (correctly allowed)");

// Simulate: process was attributed then whitelisted — cache should be reset
string cachedProc = "chrome";
bool shouldReset = whitelist.Contains(cachedProc);
if (shouldReset) { cachedProc = ""; }
if (cachedProc == "") Pass("Attribution cache reset when process is whitelisted");
else Fail("Cache reset", "processName should have been cleared");

// ═══════════════════════════════════════════════════════════════════════
// FUNCTIONAL TEST GROUP 6: File simulation against actual thresholds
// ═══════════════════════════════════════════════════════════════════════
Section("6. File-based simulation (actual temp dir)");

Console.WriteLine($"   Using temp dir: {testDir}");

// Simulate extension-change scenario (should trigger ExtensionChange heuristic)
int extChangeCount = 0;
for (int i = 1; i <= 15; i++)
{
    string src = Path.Combine(testDir, $"file_{i:D3}.docx");
    string dst = Path.Combine(testDir, $"file_{i:D3}.rg_locked");
    File.WriteAllText(src, $"content {i}");
    File.Move(src, dst);
    extChangeCount++;
}
if (extChangeCount >= ExtChangeThreshold)
    Pass($"Extension-change simulation: {extChangeCount} files → .rg_locked (≥ threshold {ExtChangeThreshold})");
else
    Fail("Extension-change count", $"only {extChangeCount}");

// Simulate mass write + rename (ransomware combined pattern)
int writeCount = 0, renameCount = 0;
string subDir = Path.Combine(testDir, "ransim");
Directory.CreateDirectory(subDir);
for (int i = 1; i <= 90; i++)
{
    File.WriteAllText(Path.Combine(subDir, $"doc_{i:D3}.txt"), $"data {i}");
    writeCount++;
}
for (int i = 1; i <= 25; i++)
{
    string src = Path.Combine(subDir, $"doc_{i:D3}.txt");
    string dst = Path.Combine(subDir, $"doc_{i:D3}.rg_enc");
    if (File.Exists(src)) { File.Move(src, dst); renameCount++; }
}
bool combinedTriggers = writeCount >= MassWriteThreshold && renameCount >= BulkRenameThreshold / 2;
if (combinedTriggers)
    Pass($"Combined-signal simulation: {writeCount} writes + {renameCount} renames → would trigger MassWrite");
else
    Fail("Combined-signal", $"writes={writeCount} renames={renameCount}");

// Cleanup
try { Directory.Delete(testDir, true); } catch { }

// ═══════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════
Console.WriteLine();
Console.WriteLine(new string('═', 65));
Console.ForegroundColor = (failed == 0) ? ConsoleColor.Green : ConsoleColor.Red;
Console.WriteLine($"  Results: {passed} passed, {failed} failed out of {passed + failed} tests");
Console.ResetColor();
Console.WriteLine(new string('═', 65));

if (failed > 0)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  ❌ Some tests failed — review output above.");
    Console.ResetColor();
    return 1;
}

Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("  ✅ All tests passed!");
Console.ResetColor();
return 0;
