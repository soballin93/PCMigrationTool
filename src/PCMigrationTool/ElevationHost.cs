using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace PCMigrationTool;

internal static class ElevationHost
{
    public static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static int Relaunch(string[] arguments, bool guiMode)
    {
        string executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The running executable path could not be resolved.");
        ProcessStartInfo startInfo = new(executable)
        {
            UseShellExecute = true,
            Verb = "runas"
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The elevated process could not be started.");
            if (guiMode)
            {
                return 0;
            }
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            if (guiMode)
            {
                MessageBox.Show(
                    "Administrator approval is required to gather or prepare a migration.",
                    "Elevation canceled",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
            return 1;
        }
    }
}
