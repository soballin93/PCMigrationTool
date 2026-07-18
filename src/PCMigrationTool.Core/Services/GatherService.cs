using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed record GatherOptions(
    string DestinationBase,
    bool IncludeOneDrive,
    bool SkipProfileCopy,
    bool AllowMissingBrowserExports,
    string ProgramVersion);

public sealed record GatherResult(RepositoryPaths Paths, MigrationManifest Manifest, string ReportPath);

public sealed class GatherService(
    SystemInventoryService inventory,
    BrowserService browserService,
    ArtifactService artifactService,
    WirelessProfileService wirelessProfiles,
    RobocopyService robocopy,
    ManifestService manifests,
    AtomicJsonFile jsonFile,
    IAppLogger logger)
{
    public async Task<GatherResult> RunAsync(
        GatherOptions options,
        CancellationToken cancellationToken = default,
        Action<string>? copyOutput = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DestinationBase);
        if (!Directory.Exists(options.DestinationBase))
        {
            throw new DirectoryNotFoundException($"Destination does not exist: {options.DestinationBase}");
        }

        EnsureFreeSpace(options.DestinationBase, options.SkipProfileCopy ? 1 : 10);
        RepositoryPaths paths = RepositoryLayout.Create(
            options.DestinationBase,
            Environment.MachineName,
            DateTimeOffset.Now);
        RepositoryLayout.EnsureDirectories(paths);
        logger.SetLogPath(paths.LogPath);
        logger.Info("=== GATHER START ===");

        IReadOnlyList<BrowserInfo> browsers = browserService.DetectInstalled();
        List<BrowserExportInfo> browserExports = browserService.ValidateExports(browsers, paths.BrowserExportsPath);
        List<BrowserExportInfo> missingExports = browserExports.Where(static export => !export.Exported).ToList();
        if (missingExports.Count > 0 && !options.AllowMissingBrowserExports)
        {
            throw new InvalidOperationException(
                "Browser exports are missing for: " + string.Join(", ", missingExports.Select(static export => export.DisplayName)));
        }

        (GeneralInfo general, ComputerInfo computer, UserInfo user) =
            await inventory.CollectAsync(options.ProgramVersion, cancellationToken).ConfigureAwait(false);
        ArtifactResults artifacts = artifactService.Gather(paths);
        bool wirelessExported = await wirelessProfiles.ExportAsync(paths.WirelessProfilesPath, cancellationToken)
            .ConfigureAwait(false);
        CopyResult? profileCopy = null;
        if (!options.SkipProfileCopy)
        {
            profileCopy = await robocopy.CopyProfileAsync(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                paths.ProfilePath,
                options.IncludeOneDrive,
                null,
                cancellationToken,
                copyOutput).ConfigureAwait(false);
            if (!profileCopy.Succeeded)
            {
                throw new IOException($"Profile copy failed with Robocopy exit code {profileCopy.ExitCode}.");
            }
        }

        List<ChecklistItem> checklist = DefaultChecklist();
        await jsonFile.WriteAsync(paths.ChecklistPath, checklist, cancellationToken).ConfigureAwait(false);
        MigrationManifest manifest = new()
        {
            General = general,
            Computer = computer,
            User = user,
            IncludeOneDrive = options.IncludeOneDrive,
            CollectedBy = $"{Environment.UserDomainName}\\{Environment.UserName}",
            CollectedAt = DateTimeOffset.Now,
            ChromeCsv = File.Exists(Path.Combine(paths.InfoRoot, "Chrome Passwords.csv")),
            BrowserPasswordExports = browserExports,
            WallpaperCopied = artifacts.WallpaperCopied,
            SignaturesCopied = artifacts.SignaturesCopied,
            DeregChecklist = checklist,
            WirelessProfilesExported = wirelessExported,
            WirelessNetworks = computer.WirelessNetworks,
            DesktopScreenshots = Directory.Exists(paths.ScreenshotsPath)
                ? Directory.EnumerateFiles(paths.ScreenshotsPath, "*.png").Select(Path.GetFileName).Where(static name => name is not null).Select(static name => name!).Order().ToList()
                : [],
            ProfileCopy = profileCopy
        };
        await manifests.SaveAsync(paths.ManifestPath, manifest, cancellationToken).ConfigureAwait(false);
        string report = await manifests.WriteReportAsync(paths, manifest, cancellationToken).ConfigureAwait(false);
        logger.Info("=== GATHER END ===");
        return new GatherResult(paths, manifest, report);
    }

    private static void EnsureFreeSpace(string path, long minimumGigabytes)
    {
        string root = Path.GetPathRoot(Path.GetFullPath(path)) ?? string.Empty;
        if (root.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return;
        }

        DriveInfo drive = new(root);
        if (drive.IsReady && drive.AvailableFreeSpace < minimumGigabytes * 1024L * 1024L * 1024L)
        {
            throw new IOException($"Destination has less than {minimumGigabytes} GB free.");
        }
    }

    private static List<ChecklistItem> DefaultChecklist() =>
    [
        new() { Name = "Microsoft 365", Notes = "Sign out or deactivate the old device if licensing requires it." },
        new() { Name = "Adobe", Notes = "Deactivate licensed Adobe applications." },
        new() { Name = "VPN and security agents", Notes = "Record enrollment or removal requirements." },
        new() { Name = "Line-of-business software", Notes = "Record license keys and deactivation steps." },
        new() { Name = "Cloud sync", Notes = "Confirm synchronization is complete before retiring the old PC." }
    ];
}
