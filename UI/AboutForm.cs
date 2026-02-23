using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Reflection;
using System.Windows.Forms;

namespace RansomGuard.UI;

/// <summary>
/// About dialog showing application information.
/// </summary>
public sealed class AboutForm : Form
{
    public AboutForm()
    {
        InitializeUI();
    }

    private void InitializeUI()
    {
        Text = "About RansomGuard";
        Size = new Size(460, 400);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Color.FromArgb(22, 22, 30);
        ForeColor = Color.White;
        Font = new Font("Segoe UI", 10F);
        ShowInTaskbar = false;

        // Gradient header panel
        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 120,
            BackColor = Color.FromArgb(28, 28, 44)
        };
        headerPanel.Paint += (_, e) =>
        {
            using var brush = new LinearGradientBrush(
                headerPanel.ClientRectangle,
                Color.FromArgb(30, 50, 90),
                Color.FromArgb(22, 22, 30),
                LinearGradientMode.Vertical);
            e.Graphics.FillRectangle(brush, headerPanel.ClientRectangle);
        };

        // Shield icon
        var shieldLabel = new Label
        {
            Text = "🛡",
            Font = new Font("Segoe UI Emoji", 40F),
            ForeColor = Color.FromArgb(80, 160, 255),
            AutoSize = true,
            Location = new Point(30, 20),
            BackColor = Color.Transparent
        };
        headerPanel.Controls.Add(shieldLabel);

        // App name
        var nameLabel = new Label
        {
            Text = "RansomGuard",
            Font = new Font("Segoe UI", 24F, FontStyle.Bold),
            ForeColor = Color.FromArgb(80, 160, 255),
            AutoSize = true,
            Location = new Point(110, 22),
            BackColor = Color.Transparent
        };
        headerPanel.Controls.Add(nameLabel);

        // Tagline
        var taglineLabel = new Label
        {
            Text = "Real-time Ransomware Detection & Protection",
            Font = new Font("Segoe UI", 9F, FontStyle.Italic),
            ForeColor = Color.FromArgb(140, 160, 190),
            AutoSize = true,
            Location = new Point(114, 68),
            BackColor = Color.Transparent
        };
        headerPanel.Controls.Add(taglineLabel);

        Controls.Add(headerPanel);

        // Info panel
        var infoPanel = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(30, 20, 30, 20)
        };

        var infoLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 6,
            BackColor = Color.Transparent
        };
        infoLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        infoLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        AddInfoRow(infoLayout, 0, "Version", "1.0.0");
        AddInfoRow(infoLayout, 1, "Framework", ".NET 8.0");
        AddInfoRow(infoLayout, 2, "Platform", "Windows x64");
        AddInfoRow(infoLayout, 3, "Architecture", "WinForms + FileSystemWatcher");
        AddInfoRow(infoLayout, 4, "License", "MIT License");

        infoPanel.Controls.Add(infoLayout);
        Controls.Add(infoPanel);

        // Features section
        var featuresLabel = new Label
        {
            Text = "Detection Heuristics:",
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            ForeColor = Color.FromArgb(160, 180, 200),
            Location = new Point(30, 248),
            AutoSize = true
        };
        Controls.Add(featuresLabel);

        var features = new Label
        {
            Text = "  ✔  Mass File Write Detection\n" +
                   "  ✔  Bulk Rename Detection\n" +
                   "  ✔  Extension Change Detection\n" +
                   "  ✔  Multi-Drive Access Monitoring\n" +
                   "  ✔  Honeypot Bait File Protection",
            Font = new Font("Segoe UI", 8.5F),
            ForeColor = Color.FromArgb(120, 200, 120),
            Location = new Point(30, 272),
            AutoSize = true
        };
        Controls.Add(features);

        // Close button
        var closeBtn = new Button
        {
            Text = "Close",
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Location = new Point(345, 355),
            Width = 90,
            Height = 32,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(50, 50, 65),
            ForeColor = Color.FromArgb(180, 180, 200),
            DialogResult = DialogResult.OK,
            Font = new Font("Segoe UI", 9F)
        };
        closeBtn.FlatAppearance.BorderColor = Color.FromArgb(70, 70, 90);
        closeBtn.FlatAppearance.MouseOverBackColor = Color.FromArgb(60, 60, 80);
        Controls.Add(closeBtn);

        AcceptButton = closeBtn;
    }

    private static void AddInfoRow(TableLayoutPanel table, int row, string label, string value)
    {
        var lblCtrl = new Label
        {
            Text = label,
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            ForeColor = Color.FromArgb(120, 130, 150),
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(0, 2, 0, 2)
        };

        var valCtrl = new Label
        {
            Text = value,
            Font = new Font("Segoe UI", 9F),
            ForeColor = Color.FromArgb(200, 200, 220),
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(0, 2, 0, 2)
        };

        table.Controls.Add(lblCtrl, 0, row);
        table.Controls.Add(valCtrl, 1, row);
    }
}
