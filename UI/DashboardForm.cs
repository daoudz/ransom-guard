using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Linq;
using RansomGuard.Core;

namespace RansomGuard.UI;

/// <summary>
/// Dashboard window showing real-time monitoring status, live event feed, and threat history.
/// </summary>
public sealed class DashboardForm : Form
{
    private readonly MonitoringEngine _engine;
    private readonly System.Windows.Forms.Timer _refreshTimer;

    // Status bar
    private Label _statusLabel = null!;
    private Label _uptimeLabel = null!;
    private Label _drivesLabel = null!;
    private Label _eventsLabel = null!;
    private Label _epsLabel = null!;

    // Live activity
    private ListView _liveList = null!;

    // Threat history
    private ListView _threatList = null!;

    // Status strip
    private Label _footerLabel = null!;

    public DashboardForm(MonitoringEngine engine)
    {
        _engine = engine;
        InitializeUI();

        _refreshTimer = new System.Windows.Forms.Timer { Interval = 1500 };
        _refreshTimer.Tick += (_, _) => RefreshData();
        _refreshTimer.Start();

        FormClosing += (_, e) =>
        {
            // Hide instead of close so we can reopen
            e.Cancel = true;
            Hide();
        };

        Load += (_, _) => RefreshData();
    }

    private void InitializeUI()
    {
        Text = "RansomGuard — Dashboard";
        Size = new Size(1050, 680);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(22, 22, 30);
        ForeColor = Color.White;
        Font = new Font("Segoe UI", 9.5F);
        MinimumSize = new Size(800, 500);
        Icon = SystemIcons.Shield;
        DoubleBuffered = true;

        // ===== TOP STATUS BAR =====
        var statusPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 90,
            BackColor = Color.FromArgb(28, 28, 40),
            Padding = new Padding(20, 10, 20, 10)
        };

        // App title
        var titleLabel = new Label
        {
            Text = "🛡  RansomGuard",
            Font = new Font("Segoe UI", 20F, FontStyle.Bold),
            ForeColor = Color.FromArgb(80, 160, 255),
            AutoSize = true,
            Location = new Point(20, 8)
        };
        statusPanel.Controls.Add(titleLabel);

        // Status indicator
        _statusLabel = new Label
        {
            Text = "● MONITORING ACTIVE",
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            ForeColor = Color.FromArgb(80, 220, 100),
            AutoSize = true,
            Location = new Point(20, 52)
        };
        statusPanel.Controls.Add(_statusLabel);

        // Stats cards (right side)
        var statsPanel = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.LeftToRight,
            AutoSize = true,
            BackColor = Color.Transparent,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Location = new Point(statusPanel.Width - 620, 12),
            Size = new Size(600, 70)
        };

        _uptimeLabel = CreateStatCard("UPTIME", "0:00:00", Color.FromArgb(80, 160, 255));
        _drivesLabel = CreateStatCard("DRIVES", "0", Color.FromArgb(160, 120, 255));
        _eventsLabel = CreateStatCard("EVENTS", "0", Color.FromArgb(255, 180, 60));
        _epsLabel = CreateStatCard("EVENTS/S", "0.0", Color.FromArgb(80, 220, 100));

        statsPanel.Controls.AddRange(new Control[] { _uptimeLabel.Parent!, _drivesLabel.Parent!, _eventsLabel.Parent!, _epsLabel.Parent! });
        statusPanel.Controls.Add(statsPanel);

        // Reposition stats on resize
        statusPanel.Resize += (_, _) =>
        {
            statsPanel.Location = new Point(statusPanel.Width - 620, 12);
        };

        Controls.Add(statusPanel);

        // ===== MAIN CONTENT AREA =====
        var splitContainer = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            BackColor = Color.FromArgb(22, 22, 30),
            SplitterWidth = 4
        };

        // Defer ALL sizing to Shown event — SplitContainer property setters
        // cross-validate each other and crash if set before layout is done
        Shown += (_, _) =>
        {
            try
            {
                splitContainer.Panel1MinSize = 200;
                splitContainer.Panel2MinSize = 200;
                splitContainer.SplitterDistance = (int)(splitContainer.Width * 0.58);
            }
            catch { }
        };

        // ---- LEFT PANEL: Live Activity Feed ----
        var livePanel = CreateSectionPanel("📡  Live Activity Feed");
        _liveList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            BackColor = Color.FromArgb(30, 30, 42),
            ForeColor = Color.FromArgb(200, 200, 210),
            Font = new Font("Cascadia Code", 8.5F, FontStyle.Regular, GraphicsUnit.Point, 0, false),
            FullRowSelect = true,
            GridLines = false,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            BorderStyle = BorderStyle.None,
            OwnerDraw = true
        };
        _liveList.Columns.Add("Time", 75);
        _liveList.Columns.Add("Type", 85);
        _liveList.Columns.Add("File Path", 300);
        _liveList.Columns.Add("Details", 150);
        _liveList.DrawColumnHeader += LiveList_DrawColumnHeader;
        _liveList.DrawItem += LiveList_DrawItem;
        _liveList.DrawSubItem += LiveList_DrawSubItem;

        // Try to load Cascadia Code, fallback to Consolas
        try
        {
            var testFont = new Font("Cascadia Code", 8.5F);
            if (testFont.Name != "Cascadia Code")
                _liveList.Font = new Font("Consolas", 8.5F);
            testFont.Dispose();
        }
        catch { _liveList.Font = new Font("Consolas", 8.5F); }

        livePanel.Controls.Add(_liveList);
        splitContainer.Panel1.Controls.Add(livePanel);

        // ---- RIGHT PANEL: Threat History ----
        var threatPanel = CreateSectionPanel("🚨  Threat History");
        _threatList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            BackColor = Color.FromArgb(30, 30, 42),
            ForeColor = Color.FromArgb(200, 200, 210),
            Font = new Font("Segoe UI", 9F),
            FullRowSelect = true,
            GridLines = false,
            HeaderStyle = ColumnHeaderStyle.Nonclickable,
            BorderStyle = BorderStyle.None,
            OwnerDraw = true
        };
        _threatList.Columns.Add("Time", 75);
        _threatList.Columns.Add("Heuristic", 95);
        _threatList.Columns.Add("Process", 100);
        _threatList.Columns.Add("Description", 200);
        _threatList.Columns.Add("Action", 80);
        _threatList.DrawColumnHeader += LiveList_DrawColumnHeader;
        _threatList.DrawItem += LiveList_DrawItem;
        _threatList.DrawSubItem += ThreatList_DrawSubItem;

        threatPanel.Controls.Add(_threatList);
        splitContainer.Panel2.Controls.Add(threatPanel);

        Controls.Add(splitContainer);

        // ===== FOOTER =====
        _footerLabel = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 28,
            BackColor = Color.FromArgb(28, 28, 40),
            ForeColor = Color.FromArgb(100, 100, 120),
            Font = new Font("Segoe UI", 8F),
            TextAlign = ContentAlignment.MiddleCenter,
            Text = "RansomGuard v1.0 — Protecting your files"
        };
        Controls.Add(_footerLabel);
    }

    private Panel CreateSectionPanel(string title)
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(26, 26, 36),
            Padding = new Padding(8, 5, 8, 8)
        };

        var header = new Label
        {
            Text = title,
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            ForeColor = Color.FromArgb(180, 180, 200),
            Dock = DockStyle.Top,
            Height = 30,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(4, 0, 0, 0)
        };
        panel.Controls.Add(header);

        return panel;
    }

    private Label CreateStatCard(string title, string value, Color accentColor)
    {
        var card = new Panel
        {
            Size = new Size(130, 62),
            BackColor = Color.FromArgb(35, 35, 50),
            Margin = new Padding(5, 2, 5, 2),
            Padding = new Padding(8, 5, 8, 5)
        };

        var titleLbl = new Label
        {
            Text = title,
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = Color.FromArgb(120, 120, 140),
            Dock = DockStyle.Top,
            Height = 18,
            TextAlign = ContentAlignment.MiddleLeft
        };

        var valueLbl = new Label
        {
            Text = value,
            Font = new Font("Segoe UI", 16F, FontStyle.Bold),
            ForeColor = accentColor,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Tag = title // Used to identify stat cards on refresh
        };

        card.Controls.Add(valueLbl);
        card.Controls.Add(titleLbl);

        return valueLbl;
    }

    private void RefreshData()
    {
        if (!Visible || IsDisposed) return;

        try
        {
            // Update status
            _statusLabel.Text = _engine.IsRunning
                ? "● MONITORING ACTIVE"
                : "○ MONITORING PAUSED";
            _statusLabel.ForeColor = _engine.IsRunning
                ? Color.FromArgb(80, 220, 100)
                : Color.FromArgb(200, 80, 80);

            // Update stats
            _uptimeLabel.Text = _engine.Uptime.ToString(@"h\:mm\:ss");
            _drivesLabel.Text = _engine.WatchedDriveCount.ToString();
            _eventsLabel.Text = FormatNumber(_engine.TotalEventsProcessed);
            _epsLabel.Text = _engine.EventsPerSecond.ToString("F1");

            // Update live activity
            var recentEvents = _engine.GetRecentEvents(100);
            _liveList.BeginUpdate();
            _liveList.Items.Clear();
            foreach (var evt in recentEvents)
            {
                var item = new ListViewItem(evt.Timestamp.ToString("HH:mm:ss"));
                item.SubItems.Add(evt.EventType);
                item.SubItems.Add(TruncatePath(evt.FilePath, 50));
                item.SubItems.Add(evt.Details);
                item.Tag = evt;
                _liveList.Items.Add(item);
            }
            _liveList.EndUpdate();

            // Update threat history
            var alerts = _engine.GetAlertHistory();
            if (_threatList.Items.Count != alerts.Count)
            {
                _threatList.BeginUpdate();
                _threatList.Items.Clear();
                foreach (var alert in alerts.OrderByDescending(a => a.DetectedAt))
                {
                    var item = new ListViewItem(alert.DetectedAt.ToString("HH:mm:ss"));
                    item.SubItems.Add(alert.HeuristicName);
                    item.SubItems.Add(alert.ProcessName);
                    item.SubItems.Add(TruncateText(alert.Description, 40));
                    item.SubItems.Add(alert.ActionTaken);
                    item.Tag = alert;
                    _threatList.Items.Add(item);
                }
                _threatList.EndUpdate();
            }

            // Footer
            _footerLabel.Text = $"RansomGuard v1.0 — {_engine.TotalEventsProcessed:N0} events processed | " +
                $"{alerts.Count} threats detected | {_engine.EventsPerSecond:F1} events/sec";
        }
        catch { } // Swallow UI refresh errors
    }

    // ===== Custom Drawing =====

    private void LiveList_DrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        using var bgBrush = new SolidBrush(Color.FromArgb(35, 35, 50));
        e.Graphics.FillRectangle(bgBrush, e.Bounds);

        using var textBrush = new SolidBrush(Color.FromArgb(140, 140, 160));
        using var font = new Font("Segoe UI", 8F, FontStyle.Bold);
        var textRect = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height);
        e.Graphics.DrawString(e.Header?.Text, font, textBrush, textRect,
            new StringFormat { LineAlignment = StringAlignment.Center });
    }

    private void LiveList_DrawItem(object? sender, DrawListViewItemEventArgs e)
    {
        // Use alternating row colors
        var bgColor = e.ItemIndex % 2 == 0
            ? Color.FromArgb(30, 30, 42)
            : Color.FromArgb(34, 34, 46);

        if (e.Item.Selected)
            bgColor = Color.FromArgb(50, 70, 100);

        using var bgBrush = new SolidBrush(bgColor);
        e.Graphics.FillRectangle(bgBrush, e.Bounds);
    }

    private void LiveList_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.SubItem == null || e.Item == null) return;

        var textColor = e.ColumnIndex switch
        {
            0 => Color.FromArgb(120, 120, 140), // Time - dim
            1 => GetEventTypeColor(e.SubItem.Text), // Type - colored
            2 => Color.FromArgb(200, 200, 210), // Path
            3 => Color.FromArgb(160, 160, 180), // Details
            _ => Color.FromArgb(200, 200, 210)
        };

        using var textBrush = new SolidBrush(textColor);
        var textRect = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height);
        var sf = new StringFormat
        {
            LineAlignment = StringAlignment.Center,
            Trimming = StringTrimming.EllipsisPath,
            FormatFlags = StringFormatFlags.NoWrap
        };
        e.Graphics.DrawString(e.SubItem.Text, e.Item.Font, textBrush, textRect, sf);
    }

    private void ThreatList_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.SubItem == null || e.Item == null) return;

        var textColor = e.ColumnIndex switch
        {
            0 => Color.FromArgb(120, 120, 140),
            1 => GetHeuristicColor(e.SubItem.Text),
            2 => Color.FromArgb(255, 200, 100),
            3 => Color.FromArgb(200, 200, 210),
            4 => GetActionColor(e.SubItem.Text),
            _ => Color.FromArgb(200, 200, 210)
        };

        using var font = e.ColumnIndex == 1
            ? new Font("Segoe UI", 8F, FontStyle.Bold)
            : e.Item.Font;
        using var textBrush = new SolidBrush(textColor);
        var textRect = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height);
        var sf = new StringFormat
        {
            LineAlignment = StringAlignment.Center,
            Trimming = StringTrimming.EllipsisCharacter,
            FormatFlags = StringFormatFlags.NoWrap
        };
        e.Graphics.DrawString(e.SubItem.Text, font, textBrush, textRect, sf);
    }

    private static Color GetEventTypeColor(string type) => type switch
    {
        "Created" => Color.FromArgb(80, 220, 100),
        "Changed" => Color.FromArgb(100, 180, 255),
        "Deleted" => Color.FromArgb(255, 100, 100),
        "Renamed" => Color.FromArgb(255, 200, 60),
        "ExtChange" => Color.FromArgb(255, 100, 60),
        _ => Color.FromArgb(180, 180, 200)
    };

    private static Color GetHeuristicColor(string heuristic) => heuristic switch
    {
        "Honeypot" => Color.FromArgb(255, 60, 60),
        "ExtensionChange" => Color.FromArgb(255, 120, 40),
        "BulkRename" => Color.FromArgb(255, 180, 40),
        "MassWrite" => Color.FromArgb(200, 160, 40),
        "MultiDrive" => Color.FromArgb(160, 100, 220),
        _ => Color.FromArgb(180, 180, 200)
    };

    private static Color GetActionColor(string action) => action switch
    {
        "Killed" => Color.FromArgb(255, 80, 80),
        "Ignored" => Color.FromArgb(180, 180, 190),
        "Whitelisted" => Color.FromArgb(80, 160, 255),
        "Pending" => Color.FromArgb(255, 200, 60),
        _ => Color.FromArgb(180, 180, 200)
    };

    private static string TruncatePath(string path, int maxLen)
    {
        if (path.Length <= maxLen) return path;
        return "..." + path[^(maxLen - 3)..];
    }

    private static string TruncateText(string text, int maxLen)
    {
        if (text.Length <= maxLen) return text;
        return text[..maxLen] + "...";
    }

    private static string FormatNumber(long n)
    {
        if (n >= 1_000_000) return $"{n / 1_000_000.0:F1}M";
        if (n >= 1_000) return $"{n / 1_000.0:F1}K";
        return n.ToString();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _refreshTimer.Stop();
            _refreshTimer.Dispose();
        }
        base.Dispose(disposing);
    }
}
