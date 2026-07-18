using System.Runtime.InteropServices;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool;

internal enum AppMode
{
    Gui,
    Gather,
    PrepareRestore,
    ResumeSystem,
    ResumeUser
}

internal sealed class CommandLine
{
    private readonly Dictionary<string, string?> values = new(StringComparer.OrdinalIgnoreCase);

    private CommandLine(AppMode mode)
    {
        Mode = mode;
    }

    public AppMode Mode { get; }
    public string? this[string name] => values.GetValueOrDefault(name);
    public bool Has(string name) => values.ContainsKey(name);

    public static CommandLine Parse(string[] args)
    {
        AppMode mode = args.Contains("--gather", StringComparer.OrdinalIgnoreCase) ? AppMode.Gather
            : args.Contains("--prepare-restore", StringComparer.OrdinalIgnoreCase) ? AppMode.PrepareRestore
            : args.Contains("--resume-system", StringComparer.OrdinalIgnoreCase) ? AppMode.ResumeSystem
            : args.Contains("--resume-user", StringComparer.OrdinalIgnoreCase) ? AppMode.ResumeUser
            : AppMode.Gui;
        CommandLine result = new(mode);
        for (int index = 0; index < args.Length; index++)
        {
            string argument = args[index];
            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }
            string? value = index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[++index]
                : null;
            result.values[argument] = value;
        }
        return result;
    }

    public string Required(string name) => this[name]
        ?? throw new ArgumentException($"Required option is missing: {name}");
}

internal static class CommandLineHost
{
    private const int AttachParentProcess = -1;

    public static async Task<int> RunAsync(CommandLine command, AppServices services)
    {
        _ = AttachConsole(AttachParentProcess);
        try
        {
            services.Logger.EntryWritten += (_, entry) => Console.Error.WriteLine(entry);
            string? artifact = null;
            string message;
            switch (command.Mode)
            {
                case AppMode.Gather:
                    GatherResult gathered = await services.Gather.RunAsync(new GatherOptions(
                        command.Required("--destination"),
                        command.Has("--include-onedrive"),
                        command.Has("--skip-profile-copy"),
                        command.Has("--allow-missing-browser-exports"),
                        Program.Version));
                    Console.Out.WriteLine(gathered.Paths.ManifestPath);
                    artifact = gathered.Paths.ManifestPath;
                    message = "Gather completed.";
                    break;

                case AppMode.PrepareRestore:
                    RestorePreparation prepared = await services.Restore.PrepareAsync(new RestoreOptions(
                        command.Required("--manifest"),
                        command["--new-hostname"],
                        command["--profile-source"],
                        command.Required("--local-user"),
                        null,
                        command.Has("--make-admin"),
                        null,
                        !command.Has("--no-resume-tasks")));
                    message = prepared.RebootRequired ? "Restore prepared; reboot required." : "Restore prepared.";
                    artifact = prepared.CachedStatePath;
                    Console.Out.WriteLine(prepared.RebootRequired ? "reboot-required" : "prepared");
                    break;

                case AppMode.ResumeSystem:
                    await services.Resume.RunSystemAsync(command.Required("--state"));
                    message = "System resume completed.";
                    artifact = command["--state"];
                    break;

                case AppMode.ResumeUser:
                    await services.Resume.RunUserAsync(command.Required("--state"));
                    message = "User resume completed.";
                    artifact = command["--state"];
                    break;

                default:
                    return 2;
            }
            await WriteResultAsync(command, services, 0, message, artifact);
            return 0;
        }
        catch (Exception exception)
        {
            services.Logger.Error("Command failed", exception);
            Console.Error.WriteLine(exception);
            await WriteResultAsync(command, services, 1, exception.Message, null);
            return 1;
        }
    }

    private static async Task WriteResultAsync(
        CommandLine command,
        AppServices services,
        int exitCode,
        string message,
        string? artifact)
    {
        string? path = command["--result-file"];
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            await services.Json.WriteAsync(path, new HeadlessCommandResult(
                command.Mode.ToString(),
                exitCode,
                exitCode == 0,
                message,
                artifact,
                DateTimeOffset.Now));
        }
        catch (Exception exception)
        {
            services.Logger.Warning($"Unable to write command result file '{path}': {exception.Message}");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(int processId);
}

internal sealed record HeadlessCommandResult(
    string Mode,
    int ExitCode,
    bool Succeeded,
    string Message,
    string? Artifact,
    DateTimeOffset CompletedAt);
