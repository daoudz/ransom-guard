# 🛡️ RansomGuard

**Real-time ransomware detection and process termination for Windows.**

RansomGuard monitors every fixed and removable drive on your machine for file activity patterns that match known ransomware behavior — and alerts you (or kills the offending process) before your files are gone.

> ⬇️ **[Download RansomGuard.exe → v1.0.0](https://github.com/daoudz/ransom-guard/releases/download/v1.0.0/RansomGuard.exe)**  
> **72 MB · Self-contained · No installation needed · Windows 10/11 x64**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Multi-drive monitoring** | Watches all fixed and removable drives simultaneously using `FileSystemWatcher` |
| 🍯 **Honeypot files** | Deploys decoy files across your drives; any process that touches them triggers an immediate high-confidence alert |
| 🔄 **Extension-change detection** | Flags mass renaming of files to consistent unknown extensions — the signature move of encryption ransomware |
| 📦 **Bulk rename + write detection** | Detects combined bursts of renames and writes within a 30-second sliding window |
| 💾 **Mass write detection** | Alerts on extremely high write volumes when accompanied by suspicious rename patterns |
| 🌐 **Multi-drive spread detection** | Catches ransomware worm behavior — simultaneous writes across 3+ drives |
| ✅ **Smart whitelisting** | Built-in trusted process list (browsers, AV, IDEs, Teams, Slack, etc.) prevents false positives; add your own in Settings |
| 🚫 **Ignore paths** | Exclude any folder from monitoring (e.g. sync folders, VMs) |
| 📊 **Live dashboard** | Dark-themed real-time activity feed showing events/sec, uptime, drive count, and full threat history |
| 🔔 **System tray** | Runs silently in the background; pops up an alert dialog when a threat is detected |



## 🚀 Getting Started

### Download & Run (recommended)

1. Download **[RansomGuard.exe](https://github.com/daoudz/ransom-guard/releases/latest/download/RansomGuard.exe)** from the latest release
2. Run it — no installation required (self-contained .NET app)
3. RansomGuard starts monitoring immediately and sits in your system tray
4. Right-click the tray icon to open the Dashboard or Settings

> **Note:** Windows SmartScreen may warn you on first run since the binary is unsigned. Click "More info → Run anyway" to proceed.

### Build from Source

**Requirements:**
- Windows 10/11 (x64)
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

```bash
git clone https://github.com/daoudz/ransom-guard.git
cd ransom-guard
dotnet run
```

To produce a self-contained executable:

```bash
dotnet publish -c Release -r win-x64 --self-contained true -o publish
```

---

## 🔬 How Detection Works

RansomGuard uses a **layered heuristic engine** designed to minimize false positives from everyday apps (browsers, antivirus, IDEs) while catching real ransomware patterns:

### Heuristics

```
1. Honeypot       — Decoy files deployed to each drive root.
                    Any write/rename to a honeypot = immediate alert.

2. ExtensionChange — 10+ files renamed to a consistent *unknown* extension
                    within 30 seconds in the same directory.
                    (Suppressed if all new extensions are benign: .tmp, .bak, etc.)

3. BulkRename     — 20+ renames AND 20+ writes in the same directory window.
                    Standalone renames from file managers are not flagged.

4. MassWrite      — 80+ writes combined with 5+ extension changes OR 10+ renames.
                    Standalone high write counts from browsers/AV are NOT flagged.

5. MultiDrive     — Writes detected on 3+ distinct drives within 30 seconds.
```

### False-Positive Suppression

- **Built-in noise filter:** Chrome, Edge, Firefox, Teams, Slack, Discord, Spotify, Windows Defender, npm, NuGet, pip, `.vs/`, `node_modules/`, and more are excluded from monitoring paths.
- **Process whitelisting:** Trusted processes are never alerted on, even if their I/O triggers a threshold.
- **Cooldown periods:** Each directory has a 2-minute cooldown after alerting to prevent alert storms.
- **Benign extension pairs:** Known safe transitions (`.tmp→.docx`, `.crdownload→.exe`, etc.) are always suppressed.

---

## ⚙️ Settings

| Setting | Description |
|---|---|
| **Whitelist processes** | Pick from running processes or browse for an `.exe` to never alert on |
| **Ignore paths** | Add folder paths to exclude from monitoring entirely |
| **Run at startup** | Register RansomGuard in the Windows startup registry |

---

## 🧪 Testing

A ransomware simulator (`RansomSim`) is included in `TestTools/RansomSim/` for safely testing the detection engine without real malware.

```bash
cd TestTools/RansomSim
dotnet run -- --help
```

---

## 📋 Requirements

- **OS:** Windows 10 / Windows 11 (x64)
- **Runtime:** Self-contained (no .NET installation needed for the release build)
- **Permissions:** Standard user account; some drive-level watchers may require elevated privileges on restricted paths

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">Made with ❤️ to keep your files safe.</p>
