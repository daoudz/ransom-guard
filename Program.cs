using System;
using System.Threading;
using System.Windows.Forms;

namespace RansomGuard;

internal static class Program
{
    private static Mutex? _mutex;

    [STAThread]
    static void Main()
    {
        // Ensure only one instance runs at a time
        const string mutexName = "Global\\RansomGuard_SingleInstance";
        _mutex = new Mutex(true, mutexName, out bool createdNew);

        if (!createdNew)
        {
            MessageBox.Show(
                "RansomGuard is already running.\nCheck the system tray.",
                "RansomGuard",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        Application.Run(new MainContext());

        _mutex.ReleaseMutex();
        _mutex.Dispose();
    }
}