using System;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using RansomGuard.Core;

namespace RansomGuard.UI;

/// <summary>
/// Settings form for managing whitelist and ignore paths.
/// </summary>
public sealed class SettingsForm : Form
{
    private readonly MonitoringEngine _engine;
    private readonly TabControl _tabs;
    private ListView _whitelistView = null!;
    private ListView _ignoreListView = null!;

    public SettingsForm(MonitoringEngine engine)
    {
        _engine = engine;
        _tabs = new TabControl();
        InitializeUI();
        Load += (_, _) => RefreshAll();
    }

    private void InitializeUI()
    {
        Text = "RansomGuard — Settings";
        Size = new Size(600, 500);
        MinimumSize = new Size(480, 380);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(26, 26, 36);
        ForeColor = Color.White;
        Font = new Font("Segoe UI", 9.5F);
        Icon = SystemIcons.Shield;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;

        // Header
        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 55,
            BackColor = Color.FromArgb(28, 28, 40),
            Padding = new Padding(16, 10, 16, 10)
        };
        var titleLbl = new Label
        {
            Text = "⚙  Settings",
            Font = new Font("Segoe UI", 16F, FontStyle.Bold),
            ForeColor = Color.FromArgb(200, 200, 220),
            AutoSize = true,
            Location = new Point(16, 12)
        };
        header.Controls.Add(titleLbl);
        Controls.Add(header);

        // Tab control
        _tabs.Dock = DockStyle.Fill;
        _tabs.Font = new Font("Segoe UI", 10F);
        _tabs.Padding = new Point(14, 6);

        // --- Whitelist Tab ---
        var whitelistTab = new TabPage("  Process Whitelist  ")
        {
            BackColor = Color.FromArgb(30, 30, 42),
            Padding = new Padding(12)
        };

        var whitelistDesc = new Label
        {
            Text = "Whitelisted processes are never flagged as suspicious. Add process names (e.g. \"notepad\") to prevent false positives.",
            ForeColor = Color.FromArgb(150, 150, 170),
            Font = new Font("Segoe UI", 8.5F),
            Dock = DockStyle.Top,
            Height = 42,
            Padding = new Padding(0, 4, 0, 8)
        };
        whitelistTab.Controls.Add(whitelistDesc);

        _whitelistView = CreateListView("Process Name");
        whitelistTab.Controls.Add(_whitelistView);

        var whitelistBtns = CreateButtonPanel(
            ("  ➕ Add Process  ", OnAddWhitelist),
            ("  ❌ Remove Selected  ", OnRemoveWhitelist));
        whitelistTab.Controls.Add(whitelistBtns);

        _tabs.TabPages.Add(whitelistTab);

        // --- Ignore Paths Tab ---
        var ignoreTab = new TabPage("  Ignore Paths  ")
        {
            BackColor = Color.FromArgb(30, 30, 42),
            Padding = new Padding(12)
        };

        var ignoreDesc = new Label
        {
            Text = "Files in these directories will be excluded from monitoring. Use this for known safe locations that generate heavy file activity.",
            ForeColor = Color.FromArgb(150, 150, 170),
            Font = new Font("Segoe UI", 8.5F),
            Dock = DockStyle.Top,
            Height = 42,
            Padding = new Padding(0, 4, 0, 8)
        };
        ignoreTab.Controls.Add(ignoreDesc);

        _ignoreListView = CreateListView("Directory Path");
        ignoreTab.Controls.Add(_ignoreListView);

        var ignoreBtns = CreateButtonPanel(
            ("  📁 Add Folder  ", OnAddIgnorePath),
            ("  ❌ Remove Selected  ", OnRemoveIgnorePath));
        ignoreTab.Controls.Add(ignoreBtns);

        _tabs.TabPages.Add(ignoreTab);

        // --- Trusted Apps Tab (read-only) ---
        var trustedTab = new TabPage("  Trusted Apps  ")
        {
            BackColor = Color.FromArgb(30, 30, 42),
            Padding = new Padding(12)
        };

        var trustedDesc = new Label
        {
            Text = "These processes are pre-trusted by RansomGuard and will never trigger alerts. " +
                   "This list covers common browsers, Windows system processes, Microsoft apps, " +
                   "antivirus software, and developer tools.",
            ForeColor = Color.FromArgb(150, 150, 170),
            Font = new Font("Segoe UI", 8.5F),
            Dock = DockStyle.Top,
            Height = 52,
            Padding = new Padding(0, 4, 0, 8)
        };
        trustedTab.Controls.Add(trustedDesc);

        var trustedView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            BackColor = Color.FromArgb(34, 34, 48),
            ForeColor = Color.FromArgb(160, 200, 160),   // soft green — read-only feel
            Font = new Font("Consolas", 9.5F),
            FullRowSelect = true,
            GridLines = false,
            BorderStyle = BorderStyle.None,
            HeaderStyle = ColumnHeaderStyle.Nonclickable
        };
        trustedView.Columns.Add("Process Name", 220);
        trustedView.Columns.Add("Category", 280);

        // Populate trusted list with categories
        foreach (var (name, category) in GetTrustedWithCategories())
        {
            var item = new ListViewItem(name);
            item.SubItems.Add(category);
            trustedView.Items.Add(item);
        }

        trustedTab.Controls.Add(trustedView);

        var readOnlyNote = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 36,
            BackColor = Color.FromArgb(34, 34, 48)
        };
        var noteLbl = new Label
        {
            Text = "🔒  Read-only — managed by RansomGuard. Use the Process Whitelist tab to add your own entries.",
            ForeColor = Color.FromArgb(100, 140, 100),
            Font = new Font("Segoe UI", 8F),
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(8, 0, 0, 0)
        };
        readOnlyNote.Controls.Add(noteLbl);
        trustedTab.Controls.Add(readOnlyNote);

        _tabs.TabPages.Add(trustedTab);

        Controls.Add(_tabs);
    }

    /// <summary>
    /// Returns the trusted process list entries paired with a human-readable category label.
    /// </summary>
    private static IEnumerable<(string Name, string Category)> GetTrustedWithCategories()
    {
        var categories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Browsers
            ["chrome"] = "Web Browser", ["msedge"] = "Web Browser", ["firefox"] = "Web Browser",
            ["opera"] = "Web Browser",  ["brave"] = "Web Browser",  ["vivaldi"] = "Web Browser",
            ["iexplore"] = "Web Browser", ["chromium"] = "Web Browser",
            // Office
            ["winword"] = "Microsoft Office", ["excel"] = "Microsoft Office",
            ["powerpnt"] = "Microsoft Office", ["outlook"] = "Microsoft Office",
            ["onenote"] = "Microsoft Office", ["msaccess"] = "Microsoft Office",
            ["mspub"] = "Microsoft Office",   ["visio"] = "Microsoft Office",
            // Communication
            ["teams"] = "Communication", ["msteams"] = "Communication",
            ["slack"] = "Communication", ["discord"] = "Communication",
            ["zoom"] = "Communication",  ["skype"] = "Communication",
            // Windows System
            ["svchost"] = "Windows System",    ["explorer"] = "Windows System",
            ["taskhostw"] = "Windows System",   ["winlogon"] = "Windows System",
            ["lsass"] = "Windows System",       ["services"] = "Windows System",
            ["msiexec"] = "Windows System",     ["dwm"] = "Windows System",
            ["wuauclt"] = "Windows Update",     ["trustedinstaller"] = "Windows Update",
            ["tiworker"] = "Windows Update",    ["usocoreworker"] = "Windows Update",
            ["searchindexer"] = "Windows Search", ["searchhost"] = "Windows Search",
            // Cloud / Sync
            ["onedrive"] = "Cloud Sync", ["dropbox"] = "Cloud Sync",
            ["googledrive"] = "Cloud Sync", ["box"] = "Cloud Sync",
            // Antivirus / Security
            ["msmpeng"] = "Security / AV",     ["mssense"] = "Security / AV",
            ["mbam"] = "Security / AV",         ["avguard"] = "Security / AV",
            ["avp"] = "Security / AV",           ["bdagent"] = "Security / AV",
            ["ekrn"] = "Security / AV",          ["mcshield"] = "Security / AV",
            // Developer Tools
            ["devenv"] = "Developer Tools",  ["code"] = "Developer Tools",
            ["msbuild"] = "Developer Tools", ["dotnet"] = "Developer Tools",
            ["git"] = "Developer Tools",     ["node"] = "Developer Tools",
            ["python"] = "Developer Tools",  ["cargo"] = "Developer Tools",
            ["rider"] = "Developer Tools",   ["idea"] = "Developer Tools",
            // Package Managers
            ["npm"] = "Package Manager", ["nuget"] = "Package Manager",
            ["winget"] = "Package Manager", ["choco"] = "Package Manager",
            // Media
            ["spotify"] = "Media", ["steam"] = "Media", ["acrobat"] = "Media",
        };

        foreach (var name in TrustedProcessList.Entries)
        {
            var category = categories.TryGetValue(name, out var cat) ? cat : "System / Utility";
            yield return (name, category);
        }
    }

    private ListView CreateListView(string columnName)
    {
        var lv = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            BackColor = Color.FromArgb(34, 34, 48),
            ForeColor = Color.FromArgb(200, 200, 210),
            Font = new Font("Consolas", 9.5F),
            FullRowSelect = true,
            GridLines = false,
            BorderStyle = BorderStyle.None,
            HeaderStyle = ColumnHeaderStyle.Nonclickable
        };
        lv.Columns.Add(columnName, 500);
        return lv;
    }

    private Panel CreateButtonPanel(params (string Text, EventHandler Handler)[] buttons)
    {
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 46,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 6, 0, 0)
        };

        foreach (var (text, handler) in buttons)
        {
            var btn = new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                BackColor = text.Contains("Remove")
                    ? Color.FromArgb(80, 40, 40)
                    : Color.FromArgb(40, 60, 90),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Height = 34,
                AutoSize = true,
                Padding = new Padding(8, 0, 8, 0),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderColor = text.Contains("Remove")
                ? Color.FromArgb(130, 60, 60)
                : Color.FromArgb(70, 100, 150);
            btn.FlatAppearance.MouseOverBackColor = text.Contains("Remove")
                ? Color.FromArgb(110, 50, 50)
                : Color.FromArgb(50, 80, 120);
            btn.Click += handler;
            panel.Controls.Add(btn);
        }

        return panel;
    }

    private void RefreshAll()
    {
        RefreshWhitelist();
        RefreshIgnoreList();
    }

    private void RefreshWhitelist()
    {
        _whitelistView.Items.Clear();
        foreach (var proc in _engine.GetWhitelist())
        {
            _whitelistView.Items.Add(new ListViewItem(proc));
        }
    }

    private void RefreshIgnoreList()
    {
        _ignoreListView.Items.Clear();
        foreach (var path in _engine.GetIgnorePaths())
        {
            _ignoreListView.Items.Add(new ListViewItem(path));
        }
    }

    private void OnAddWhitelist(object? sender, EventArgs e)
    {
        var result = ShowProcessPickerDialog();
        if (!string.IsNullOrWhiteSpace(result))
        {
            _engine.WhitelistProcess(result);
            RefreshWhitelist();
        }
    }

    private void OnRemoveWhitelist(object? sender, EventArgs e)
    {
        if (_whitelistView.SelectedItems.Count == 0)
        {
            ShowMessage("Select a process to remove.");
            return;
        }

        var procName = _whitelistView.SelectedItems[0].Text;
        _engine.RemoveFromWhitelist(procName);
        RefreshWhitelist();
    }

    private void OnAddIgnorePath(object? sender, EventArgs e)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select a folder to ignore during monitoring",
            ShowNewFolderButton = false
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _engine.AddIgnorePath(dialog.SelectedPath);
            RefreshIgnoreList();
        }
    }

    private void OnRemoveIgnorePath(object? sender, EventArgs e)
    {
        if (_ignoreListView.SelectedItems.Count == 0)
        {
            ShowMessage("Select a path to remove.");
            return;
        }

        var path = _ignoreListView.SelectedItems[0].Text;
        _engine.RemoveIgnorePath(path);
        RefreshIgnoreList();
    }

    /// <summary>
    /// Shows a dialog with running processes (searchable) + a browse button.
    /// Returns the selected process name, or null if cancelled.
    /// </summary>
    private string? ShowProcessPickerDialog()
    {
        string? selectedProcess = null;

        var dlg = new Form
        {
            Text = "Add Process to Whitelist",
            Size = new Size(640, 520),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = Color.FromArgb(26, 26, 36),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9.5F),
            ShowInTaskbar = false
        };

        // Header
        var headerLbl = new Label
        {
            Text = "Select a running process or browse for an executable:",
            Location = new Point(16, 14),
            AutoSize = true,
            ForeColor = Color.FromArgb(180, 180, 200),
            Font = new Font("Segoe UI", 9.5F)
        };
        dlg.Controls.Add(headerLbl);

        // Search box
        var searchBox = new TextBox
        {
            Location = new Point(16, 42),
            Width = 470,
            Height = 28,
            BackColor = Color.FromArgb(38, 38, 52),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10F),
            BorderStyle = BorderStyle.FixedSingle,
            PlaceholderText = "🔍  Type to filter processes..."
        };
        dlg.Controls.Add(searchBox);

        // Browse button (next to search)
        var browseBtn = new Button
        {
            Text = "📂 Browse .exe",
            Location = new Point(496, 40),
            Width = 120,
            Height = 30,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(50, 60, 80),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        browseBtn.FlatAppearance.BorderColor = Color.FromArgb(70, 90, 120);
        browseBtn.FlatAppearance.MouseOverBackColor = Color.FromArgb(60, 75, 100);
        dlg.Controls.Add(browseBtn);

        // Process list
        var procList = new ListView
        {
            Location = new Point(16, 78),
            Size = new Size(600, 350),
            View = View.Details,
            BackColor = Color.FromArgb(32, 32, 46),
            ForeColor = Color.FromArgb(200, 200, 210),
            Font = new Font("Segoe UI", 9F),
            FullRowSelect = true,
            GridLines = false,
            BorderStyle = BorderStyle.None,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            MultiSelect = false
        };
        procList.Columns.Add("Process Name", 180);
        procList.Columns.Add("PID", 65);
        procList.Columns.Add("Path", 340);
        dlg.Controls.Add(procList);

        // Bottom buttons
        var addBtn = new Button
        {
            Text = "  ✔ Add to Whitelist  ",
            Location = new Point(370, 440),
            Width = 145,
            Height = 34,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(40, 100, 60),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            Cursor = Cursors.Hand,
            Enabled = false
        };
        addBtn.FlatAppearance.BorderColor = Color.FromArgb(60, 140, 80);
        addBtn.FlatAppearance.MouseOverBackColor = Color.FromArgb(50, 120, 70);
        dlg.Controls.Add(addBtn);

        var cancelBtn = new Button
        {
            Text = "Cancel",
            Location = new Point(526, 440),
            Width = 90,
            Height = 34,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(55, 55, 70),
            ForeColor = Color.FromArgb(180, 180, 200),
            DialogResult = DialogResult.Cancel
        };
        cancelBtn.FlatAppearance.BorderColor = Color.FromArgb(75, 75, 95);
        dlg.Controls.Add(cancelBtn);
        dlg.CancelButton = cancelBtn;

        // Load running processes
        var allProcessItems = new System.Collections.Generic.List<ListViewItem>();
        try
        {
            var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    if (proc.Id <= 4) continue;
                    if (seen.Contains(proc.ProcessName)) { proc.Dispose(); continue; }
                    seen.Add(proc.ProcessName);

                    string path = "";
                    try { path = proc.MainModule?.FileName ?? ""; } catch { }

                    var item = new ListViewItem(proc.ProcessName);
                    item.SubItems.Add(proc.Id.ToString());
                    item.SubItems.Add(path);
                    item.Tag = proc.ProcessName;
                    allProcessItems.Add(item);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        // Sort by name
        allProcessItems.Sort((a, b) =>
            string.Compare(a.Text, b.Text, StringComparison.OrdinalIgnoreCase));

        void PopulateList(string filter)
        {
            procList.BeginUpdate();
            procList.Items.Clear();
            foreach (var item in allProcessItems)
            {
                if (string.IsNullOrEmpty(filter)
                    || item.Text.Contains(filter, StringComparison.OrdinalIgnoreCase)
                    || (item.SubItems.Count > 2 && item.SubItems[2].Text.Contains(filter, StringComparison.OrdinalIgnoreCase)))
                {
                    procList.Items.Add((ListViewItem)item.Clone());
                }
            }
            procList.EndUpdate();
        }

        PopulateList("");

        // Events
        searchBox.TextChanged += (_, _) => PopulateList(searchBox.Text);

        procList.SelectedIndexChanged += (_, _) =>
        {
            addBtn.Enabled = procList.SelectedItems.Count > 0;
        };

        procList.DoubleClick += (_, _) =>
        {
            if (procList.SelectedItems.Count > 0)
            {
                selectedProcess = procList.SelectedItems[0].Tag?.ToString();
                dlg.DialogResult = DialogResult.OK;
                dlg.Close();
            }
        };

        addBtn.Click += (_, _) =>
        {
            if (procList.SelectedItems.Count > 0)
            {
                selectedProcess = procList.SelectedItems[0].Tag?.ToString();
                dlg.DialogResult = DialogResult.OK;
                dlg.Close();
            }
        };

        browseBtn.Click += (_, _) =>
        {
            using var openFile = new OpenFileDialog
            {
                Title = "Select an executable to whitelist",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
            };
            if (openFile.ShowDialog(dlg) == DialogResult.OK)
            {
                selectedProcess = System.IO.Path.GetFileNameWithoutExtension(openFile.FileName);
                dlg.DialogResult = DialogResult.OK;
                dlg.Close();
            }
        };

        return dlg.ShowDialog(this) == DialogResult.OK ? selectedProcess : null;
    }

    private void ShowMessage(string msg)
    {
        MessageBox.Show(this, msg, "RansomGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
