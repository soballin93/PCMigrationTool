using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed record PrinterRestoreResult(string Name, bool Succeeded, string Message);

public sealed class PrinterRestoreService(IProcessRunner processRunner, IAppLogger logger)
{
    public async Task<IReadOnlyList<PrinterRestoreResult>> RestoreSharedPrintersAsync(
        IEnumerable<PrinterInfo> printers,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(printers);
        List<PrinterRestoreResult> results = [];
        foreach (PrinterInfo printer in printers)
        {
            string connection = SharedConnectionName(printer);
            if (connection.Length == 0)
            {
                continue;
            }

            ProcessResult process = await processRunner.RunAsync(
                "rundll32.exe",
                ["printui.dll,PrintUIEntry", "/in", "/q", "/n", connection],
                TimeSpan.FromMinutes(2),
                cancellationToken).ConfigureAwait(false);
            if (process.Succeeded)
            {
                logger.Info($"Restored shared printer '{connection}'.");
                results.Add(new(connection, true, "Connected."));
            }
            else
            {
                string message = string.IsNullOrWhiteSpace(process.StandardError)
                    ? $"PrintUI returned exit code {process.ExitCode}."
                    : process.StandardError.Trim();
                logger.Warning($"Shared printer '{connection}' could not be restored: {message}");
                results.Add(new(connection, false, message));
            }
        }
        return results;
    }

    public static string SharedConnectionName(PrinterInfo printer)
    {
        ArgumentNullException.ThrowIfNull(printer);
        if (printer.Name.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return printer.Name;
        }
        return printer.PortName.StartsWith(@"\\", StringComparison.Ordinal) ? printer.PortName : string.Empty;
    }
}
