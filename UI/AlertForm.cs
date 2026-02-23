using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Media;
using System.Windows.Forms;
using RansomGuard.Core;
using RansomGuard.Utils;

namespace RansomGuard.UI;

/// <summary>
/// Alert popup dialog shown when suspicious activity is detected.
/// Returns DialogResult.Abort for Kill, DialogResult.Ignore for Ignore,
/// DialogResult.OK for Ignore & Whitelist.
/// </summary>
public sealed class AlertForm : Form
{
    private readonly SuspiciousActivityEventArgs _alertData;

    public AlertForm(SuspiciousActivityEventArgs alertData)
    {
        _alertData = alertData;
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        SuspendLayout();

        // Form settings
        Text = "⚠ RansomGuard — Suspicious Activity Detected!";
        Size = new Size(580, 420);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        BackColor = Color.FromArgb(30, 30, 36);
        ForeColor = Color.White;
        ShowInTaskbar = true;
        Font = new Font("Segoe UI", 10F);

        // ===== Warning Header Panel =====
        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 60,
            BackColor = Color.FromArgb(200, 40, 40),
            Padding = new Padding(15, 0, 15, 0)
        };

        var warningLabel = new Label
        {
            Text = "⚠  SUSPICIOUS ACTIVITY DETECTED",
            Font = new Font("Segoe UI", 16F, FontStyle.Bold),
            ForeColor = Color.White,
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft
        };
        headerPanel.Controls.Add(warningLabel);
        Controls.Add(headerPanel);

        // ===== Details Panel =====
        var detailsPanel = new Panel
        {
            Location = new Point(20, 75),
            Size = new Size(530, 210),
            BackColor = Color.FromArgb(40, 40, 48),
            Padding = new Padding(15)
        };

        var yPos = 12;

        // Heuristic badge
        var heuristicBadge = new Label
        {
            Text = _alertData.HeuristicName.ToUpperInvariant(),
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = Color.White,
            BackColor = GetHeuristicColor(_alertData.HeuristicName),
            AutoSize = true,
            Padding = new Padding(6, 2, 6, 2),
            Location = new Point(15, yPos)
        };
        detailsPanel.Controls.Add(heuristicBadge);
        yPos += 30;

        // Description
        var descLabel = new Label
        {
            Text = _alertData.Description,
            Font = new Font("Segoe UI", 10F, FontStyle.Bold),
            ForeColor = Color.FromArgb(255, 200, 100),
            Location = new Point(15, yPos),
            Size = new Size(500, 40),
            AutoSize = false
        };
        detailsPanel.Controls.Add(descLabel);
        yPos += 45;

        // Process Name
        AddDetailRow(detailsPanel, "Process:", _alertData.ProcessName, ref yPos);

        // PID
        AddDetailRow(detailsPanel, "PID:", _alertData.ProcessId > 0 ? _alertData.ProcessId.ToString() : "Unknown", ref yPos);

        // Process Path
        var pathText = string.IsNullOrEmpty(_alertData.ProcessPath) ? "Unknown" : _alertData.ProcessPath;
        AddDetailRow(detailsPanel, "Path:", pathText, ref yPos);

        // Trigger File
        if (!string.IsNullOrEmpty(_alertData.TriggerFile))
        {
            var triggerDisplay = _alertData.TriggerFile.Length > 60
                ? "..." + _alertData.TriggerFile[^57..]
                : _alertData.TriggerFile;
            AddDetailRow(detailsPanel, "File:", triggerDisplay, ref yPos);
        }

        // Time
        AddDetailRow(detailsPanel, "Time:", _alertData.DetectedAt.ToString("HH:mm:ss"), ref yPos);

        Controls.Add(detailsPanel);

        // ===== Buttons Panel =====
        var buttonPanel = new Panel
        {
            Location = new Point(20, 300),
            Size = new Size(530, 55),
        };

        // Kill Process Button (RED)
        var killButton = new Button
        {
            Text = "🛑  KILL PROCESS",
            Size = new Size(160, 45),
            Location = new Point(0, 0),
            BackColor = Color.FromArgb(200, 40, 40),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            Cursor = Cursors.Hand,
            DialogResult = DialogResult.Abort
        };
        killButton.FlatAppearance.BorderSize = 0;
        killButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(230, 60, 60);
        buttonPanel.Controls.Add(killButton);

        // Ignore Button (GRAY)
        var ignoreButton = new Button
        {
            Text = "Ignore Once",
            Size = new Size(140, 45),
            Location = new Point(175, 0),
            BackColor = Color.FromArgb(70, 70, 80),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10F),
            Cursor = Cursors.Hand,
            DialogResult = DialogResult.Cancel
        };
        ignoreButton.FlatAppearance.BorderSize = 0;
        ignoreButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(90, 90, 100);
        buttonPanel.Controls.Add(ignoreButton);

        // Ignore & Whitelist Button (BLUE-GRAY)
        var whitelistButton = new Button
        {
            Text = "Ignore & Whitelist",
            Size = new Size(175, 45),
            Location = new Point(330, 0),
            BackColor = Color.FromArgb(50, 80, 120),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 10F),
            Cursor = Cursors.Hand,
            DialogResult = DialogResult.Ignore
        };
        whitelistButton.FlatAppearance.BorderSize = 0;
        whitelistButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(70, 100, 150);
        buttonPanel.Controls.Add(whitelistButton);

        Controls.Add(buttonPanel);

        // ===== Footer =====
        var footerLabel = new Label
        {
            Text = $"Detected at {_alertData.DetectedAt:yyyy-MM-dd HH:mm:ss}  |  RansomGuard v1.0",
            Font = new Font("Segoe UI", 8F),
            ForeColor = Color.FromArgb(120, 120, 130),
            Dock = DockStyle.Bottom,
            Height = 25,
            TextAlign = ContentAlignment.MiddleCenter
        };
        Controls.Add(footerLabel);

        ResumeLayout(false);

        // Flash the window
        Load += (_, _) =>
        {
            FlashWindow();
            SystemSounds.Exclamation.Play();
        };

        AcceptButton = killButton;
        CancelButton = ignoreButton;
    }

    private static void AddDetailRow(Panel parent, string label, string value, ref int yPos)
    {
        var lblKey = new Label
        {
            Text = label,
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            ForeColor = Color.FromArgb(160, 160, 170),
            Location = new Point(15, yPos),
            AutoSize = true
        };
        parent.Controls.Add(lblKey);

        var lblValue = new Label
        {
            Text = value,
            Font = new Font("Segoe UI", 9F),
            ForeColor = Color.White,
            Location = new Point(90, yPos),
            Size = new Size(420, 18),
            AutoSize = false
        };
        parent.Controls.Add(lblValue);

        yPos += 22;
    }

    private static Color GetHeuristicColor(string heuristic)
    {
        return heuristic switch
        {
            "Honeypot" => Color.FromArgb(200, 40, 40),
            "BulkRename" => Color.FromArgb(200, 120, 30),
            "ExtensionChange" => Color.FromArgb(180, 60, 30),
            "MassWrite" => Color.FromArgb(160, 100, 30),
            "MultiDrive" => Color.FromArgb(120, 60, 160),
            _ => Color.FromArgb(100, 100, 110)
        };
    }

    private void FlashWindow()
    {
        var flashInfo = new NativeMethods.FLASHWINFO
        {
            cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.FLASHWINFO>(),
            hwnd = Handle,
            dwFlags = NativeMethods.FLASHW_ALL | NativeMethods.FLASHW_TIMERNOFG,
            uCount = 5,
            dwTimeout = 0
        };
        NativeMethods.FlashWindowEx(ref flashInfo);
    }
}
