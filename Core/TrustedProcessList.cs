namespace RansomGuard.Core;

/// <summary>
/// Curated list of process names that are pre-trusted at startup.
/// These are well-known, widely-used applications that legitimately
/// perform high-volume file I/O and should never trigger ransomware alerts.
///
/// Process names are without the .exe extension, lowercase, matching
/// the value returned by Process.ProcessName.
/// </summary>
public static class TrustedProcessList
{
    /// <summary>
    /// All pre-trusted process names. Seeded into the whitelist at startup.
    /// </summary>
    public static readonly IReadOnlyList<string> Entries = new[]
    {
        // ── Web Browsers ──────────────────────────────────────────────────────
        "chrome",           // Google Chrome
        "msedge",           // Microsoft Edge
        "firefox",          // Mozilla Firefox
        "opera",            // Opera
        "brave",            // Brave Browser
        "vivaldi",          // Vivaldi
        "iexplore",         // Internet Explorer (legacy)
        "chromium",         // Chromium open-source

        // ── Microsoft Office ──────────────────────────────────────────────────
        "winword",          // Microsoft Word
        "excel",            // Microsoft Excel
        "powerpnt",         // Microsoft PowerPoint
        "outlook",          // Microsoft Outlook
        "onenote",          // Microsoft OneNote
        "msaccess",         // Microsoft Access
        "mspub",            // Microsoft Publisher
        "visio",            // Microsoft Visio
        "lync",             // Skype for Business (legacy)

        // ── Microsoft Teams / Communication ───────────────────────────────────
        "teams",            // Microsoft Teams (classic)
        "msteams",          // Microsoft Teams
        "ms-teams",         // Microsoft Teams variant
        "slack",            // Slack
        "discord",          // Discord
        "zoom",             // Zoom
        "skype",            // Skype

        // ── Microsoft System & Update Processes ───────────────────────────────
        "svchost",          // Windows Service Host
        "explorer",         // Windows Explorer
        "taskhostw",        // Task Host Window
        "taskhost",         // Task Host
        "dwm",              // Desktop Window Manager
        "winlogon",         // Windows Logon
        "csrss",            // Client/Server Runtime
        "lsass",            // Local Security Authority
        "services",         // Windows Services
        "wuauclt",          // Windows Update
        "wuauclt1",
        "musnotification",  // Monthly Update Notification
        "usocoreworker",    // Update Session Orchestrator
        "trustedinstaller", // Windows Trusted Installer
        "tiworker",         // Windows Module Installer Worker
        "msiexec",          // Windows Installer
        "backgroundtaskhost", // Background Task Host
        "runtimebroker",    // Runtime Broker
        "searchindexer",    // Windows Search Indexer
        "searchhost",       // Windows Search
        "searchprotocolhost",
        "spoolsv",          // Print Spooler
        "dllhost",          // COM Surrogate
        "conhost",          // Console Window Host
        "ctfmon",           // CTF Loader (input methods)
        "sihost",           // Shell Infrastructure Host
        "fontdrvhost",      // Font Driver Host
        "wpnservice",       // Windows Push Notification Service
        "smartscreen",      // Windows SmartScreen

        // ── OneDrive / Cloud Sync ─────────────────────────────────────────────
        "onedrive",         // Microsoft OneDrive
        "dropbox",          // Dropbox
        "googledrivesync",  // Google Drive (legacy)
        "googledrive",      // Google Drive
        "box",              // Box Drive

        // ── Antivirus / Security ──────────────────────────────────────────────
        "msmpeng",          // Windows Defender Antivirus
        "mssense",          // Microsoft Defender for Endpoint
        "nissrv",           // Microsoft Network Realtime Inspection Service
        "securityhealthservice",
        "securityhealthsystray",
        "mbam",             // Malwarebytes
        "mbamservice",
        "avgnt",            // Avira
        "avguard",
        "avp",              // Kaspersky
        "mcshield",         // McAfee
        "egui",             // ESET
        "ekrn",             // ESET kernel
        "bdagent",          // Bitdefender
        "vsserv",           // Bitdefender
        "csc",              // Norton (ConnectSafe)
        "ccsvchst",         // Symantec/Norton

        // ── Developer Tools ───────────────────────────────────────────────────
        "devenv",           // Visual Studio
        "code",             // VS Code
        "code - insiders",  // VS Code Insiders
        "rider",            // JetBrains Rider
        "idea",             // JetBrains IntelliJ IDEA
        "webstorm",         // JetBrains WebStorm
        "pycharm",          // JetBrains PyCharm
        "clion",            // JetBrains CLion
        "msbuild",          // MSBuild
        "dotnet",           // .NET CLI
        "csc",              // C# Compiler
        "vbcscompiler",     // Roslyn compiler server
        "vctip",            // Visual C++ Telemetry
        "git",              // Git CLI
        "git-remote-https", // Git HTTPS
        "node",             // Node.js
        "npm",              // npm CLI
        "python",           // Python interpreter
        "python3",
        "pip",
        "pip3",
        "cargo",            // Rust package manager

        // ── Package Managers & Runtimes ──────────────────────────────────────
        "nuget",            // NuGet CLI
        "winget",           // Windows Package Manager
        "choco",            // Chocolatey

        // ── Media / Creative Apps ─────────────────────────────────────────────
        "spotify",          // Spotify
        "steam",            // Steam (updates frequently)
        "steamservice",
        "adobearm",         // Adobe Creative Cloud
        "acrobat",          // Adobe Acrobat
        "acrobatdc",
        "photoshop",
        "illustrator",
        "premiere",

        // ── System Utilities ─────────────────────────────────────────────────
        "7zg",              // 7-Zip GUI
        "7z",               // 7-Zip CLI
        "winrar",           // WinRAR
        "notepad",          // Notepad
        "notepad++",        // Notepad++
        "mspaint",          // MS Paint
        "calc",             // Calculator
        "snippingtool",     // Snipping Tool
        "taskmgr",          // Task Manager
        "regedit",          // Registry Editor
        "cmd",              // Command Prompt
        "powershell",       // PowerShell
        "pwsh",             // PowerShell Core
        "wt",               // Windows Terminal
        "robocopy",         // Robocopy
        "xcopy",            // XCopy
    };
}
