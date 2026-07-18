namespace PCMigrationTool;

internal static class Program
{
    public const string Version = "1.0.4";

    [STAThread]
    private static int Main(string[] args)
    {
        AppServices services = new();
        CommandLine command = CommandLine.Parse(args);
        if (command.Mode != AppMode.ResumeUser && !ElevationHost.IsAdministrator())
        {
            return ElevationHost.Relaunch(args, command.Mode == AppMode.Gui);
        }
        if (command.Mode != AppMode.Gui)
        {
            return CommandLineHost.RunAsync(command, services).GetAwaiter().GetResult();
        }

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, eventArgs) =>
        {
            services.Logger.Error("Unhandled UI error", eventArgs.Exception);
            MessageBox.Show(
                eventArgs.Exception.Message,
                "PC Migration Tool Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        };
        Application.Run(new MainForm(services, new ScreenCaptureService(services.Logger)));
        return 0;
    }
}
