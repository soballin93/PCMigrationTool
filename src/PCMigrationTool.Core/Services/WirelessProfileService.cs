using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool.Core.Services;

public sealed class WirelessProfileService(IProcessRunner processRunner, IAppLogger logger)
{
    public async Task<bool> ExportAsync(string destination, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(destination);
        foreach (string existing in Directory.EnumerateFiles(destination, "*.xml"))
        {
            File.Delete(existing);
        }

        ProcessResult result = await processRunner.RunAsync(
            "netsh.exe",
            ["wlan", "export", "profile", $"folder={destination}", "key=clear"],
            TimeSpan.FromMinutes(2),
            cancellationToken).ConfigureAwait(false);
        bool exported = result.Succeeded && Directory.EnumerateFiles(destination, "*.xml").Any();
        logger.Info(exported ? "Exported wireless profiles." : "No wireless profiles were exported.");
        return exported;
    }

    public async Task<int> ImportAsync(string source, CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(source))
        {
            logger.Warning($"Wireless profile folder does not exist: {source}");
            return 0;
        }

        int imported = 0;
        foreach (string profile in Directory.EnumerateFiles(source, "*.xml"))
        {
            ProcessResult result = await processRunner.RunAsync(
                "netsh.exe",
                ["wlan", "add", "profile", $"filename={profile}", "user=all"],
                TimeSpan.FromMinutes(1),
                cancellationToken).ConfigureAwait(false);
            if (result.Succeeded)
            {
                imported++;
                logger.Info($"Imported wireless profile '{Path.GetFileName(profile)}'.");
            }
            else
            {
                logger.Warning($"Failed to import wireless profile '{Path.GetFileName(profile)}'.");
            }
        }

        return imported;
    }
}
