using System;
using System.Drawing;
using System.Windows.Forms;
using RansomGuard.Core;
using RansomGuard.Utils;

namespace RansomGuard;

/// <summary>
/// Application context that runs headless with a system tray icon.
/// </summary>
internal sealed class MainContext : ApplicationContext
{
    private readonly NotifyIcon _trayIcon;
    private readonly MonitoringEngine _engine;
    private readonly ToolStripMenuItem _monitoringToggle;
    private readonly ToolStripMenuItem _startupToggle;
    private UI.DashboardForm? _dashboard;

    public MainContext()
    {
        _engine = new MonitoringEngine();
        _engine.SuspiciousActivityDetected += OnSuspiciousActivity;

        _monitoringToggle = new ToolStripMenuItem("Monitoring: ON", null, OnToggleMonitoring)
        {
            Checked = true
        };

        _startupToggle = new ToolStripMenuItem("Start with Windows", null, OnToggleStartup)
        {
            Checked = StartupManager.IsEnabled()
        };

        var contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add(new ToolStripLabel("RansomGuard v1.0") { ForeColor = Color.Gray });
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add("📊 Dashboard", null, OnOpenDashboard);
        contextMenu.Items.Add("⚙  Settings", null, OnOpenSettings);
        contextMenu.Items.Add("ℹ  About", null, OnOpenAbout);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add(_monitoringToggle);
        contextMenu.Items.Add(_startupToggle);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add("Exit", null, OnExit);

        _trayIcon = new NotifyIcon
        {
            Icon = LoadEmbeddedIcon(),
            Text = "RansomGuard — Monitoring Active",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        _trayIcon.DoubleClick += (_, _) => OnOpenDashboard(null, EventArgs.Empty);

        _engine.Start();

        _trayIcon.ShowBalloonTip(
            2000,
            "RansomGuard Started",
            $"Monitoring {_engine.WatchedDriveCount} drives for suspicious activity.\nDouble-click tray icon for dashboard.",
            ToolTipIcon.Info);
    }

    private void OnOpenDashboard(object? sender, EventArgs e)
    {
        if (_dashboard == null || _dashboard.IsDisposed)
        {
            _dashboard = new UI.DashboardForm(_engine);
        }

        if (_dashboard.Visible)
        {
            _dashboard.BringToFront();
            _dashboard.WindowState = FormWindowState.Normal;
        }
        else
        {
            _dashboard.Show();
        }
    }

    private void OnOpenSettings(object? sender, EventArgs e)
    {
        using var settingsForm = new UI.SettingsForm(_engine);
        settingsForm.ShowDialog();
    }

    private void OnOpenAbout(object? sender, EventArgs e)
    {
        using var aboutForm = new UI.AboutForm();
        aboutForm.ShowDialog();
    }

    private void OnSuspiciousActivity(object? sender, SuspiciousActivityEventArgs e)
    {
        // Marshal to UI thread
        if (_trayIcon.ContextMenuStrip?.InvokeRequired == true)
        {
            _trayIcon.ContextMenuStrip.BeginInvoke(() => ShowAlert(e));
        }
        else
        {
            ShowAlert(e);
        }
    }

    private void ShowAlert(SuspiciousActivityEventArgs e)
    {
        using var alertForm = new UI.AlertForm(e);
        _trayIcon.ShowBalloonTip(
            1500,
            "⚠ Suspicious Activity Detected!",
            $"{e.ProcessName} — {e.Description}",
            ToolTipIcon.Warning);

        var result = alertForm.ShowDialog();

        if (result == DialogResult.Abort) // Kill
        {
            e.ActionTaken = "Killed";
            try
            {
                ProcessHelper.KillProcess(e.ProcessId);
                _trayIcon.ShowBalloonTip(2000, "Process Killed",
                    $"{e.ProcessName} (PID: {e.ProcessId}) was terminated.",
                    ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not kill process: {ex.Message}",
                    "RansomGuard",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }
        else if (result == DialogResult.Ignore) // Ignore & Whitelist
        {
            e.ActionTaken = "Whitelisted";
            _engine.WhitelistProcess(e.ProcessName);
        }
        else // Cancel = Ignore Once
        {
            e.ActionTaken = "Ignored";
        }
    }

    private void OnToggleMonitoring(object? sender, EventArgs e)
    {
        if (_engine.IsRunning)
        {
            _engine.Stop();
            _monitoringToggle.Text = "Monitoring: OFF";
            _monitoringToggle.Checked = false;
            _trayIcon.Text = "RansomGuard — Monitoring Paused";
            _trayIcon.ShowBalloonTip(1500, "RansomGuard", "Monitoring paused.", ToolTipIcon.Warning);
        }
        else
        {
            _engine.Start();
            _monitoringToggle.Text = "Monitoring: ON";
            _monitoringToggle.Checked = true;
            _trayIcon.Text = "RansomGuard — Monitoring Active";
            _trayIcon.ShowBalloonTip(1500, "RansomGuard", "Monitoring resumed.", ToolTipIcon.Info);
        }
    }

    private void OnToggleStartup(object? sender, EventArgs e)
    {
        bool isEnabled = StartupManager.IsEnabled();
        if (isEnabled)
            StartupManager.Disable();
        else
            StartupManager.Enable();

        _startupToggle.Checked = !isEnabled;
    }

    private void OnExit(object? sender, EventArgs e)
    {
        _engine.Stop();
        _engine.Dispose();
        _dashboard?.Close();
        _dashboard?.Dispose();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        Application.Exit();
    }

    private static Icon LoadEmbeddedIcon()
    {
        try
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var stream = assembly.GetManifestResourceStream("RansomGuard.Resources.shield.ico");
            if (stream != null)
                return new Icon(stream);
        }
        catch { }

        return SystemIcons.Shield;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _engine.Stop();
            _engine.Dispose();
            _dashboard?.Dispose();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        base.Dispose(disposing);
    }
}
