using System.Text;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed class ResumeService(
    AtomicJsonFile jsonFile,
    ManifestService manifests,
    WirelessProfileService wirelessProfiles,
    RobocopyService robocopy,
    ArtifactService artifacts,
    MappedDriveService mappedDrives,
    PrinterRestoreService printers,
    ResumeTaskService tasks,
    IAppLogger logger)
{
    public async Task RunSystemAsync(string statePath, CancellationToken cancellationToken = default)
    {
        RestoreState state = await LoadStateAsync(statePath, cancellationToken).ConfigureAwait(false);
        RepositoryPaths paths = RepositoryLayout.FromManifest(state.ManifestPath, DateTimeOffset.Now);
        logger.SetLogPath(paths.LogPath);
        logger.Info("=== SYSTEM RESUME START ===");
        if (state.NextPhase is RestorePhases.UserProfile or RestorePhases.Complete)
        {
            logger.Info($"System resume is already complete; current phase is '{state.NextPhase}'.");
            await tasks.RemoveSystemTaskAsync(cancellationToken).ConfigureAwait(false);
            return;
        }
        if (state.NextPhase != RestorePhases.PostJoin)
        {
            throw new InvalidDataException($"Unknown restore phase '{state.NextPhase}'.");
        }
        await wirelessProfiles.ImportAsync(paths.WirelessProfilesPath, cancellationToken).ConfigureAwait(false);
        state.NextPhase = RestorePhases.UserProfile;
        state.UpdatedAt = DateTimeOffset.Now;
        await jsonFile.WriteAsync(statePath, state, cancellationToken).ConfigureAwait(false);
        await jsonFile.WriteAsync(paths.StatePath, state, cancellationToken).ConfigureAwait(false);
        await WriteSourceStateBestEffortAsync(state, cancellationToken).ConfigureAwait(false);
        await tasks.RemoveSystemTaskAsync(cancellationToken).ConfigureAwait(false);
        logger.Info("=== SYSTEM RESUME END ===");
    }

    public async Task RunUserAsync(string statePath, CancellationToken cancellationToken = default)
    {
        RestoreState state = await LoadStateAsync(statePath, cancellationToken).ConfigureAwait(false);
        RepositoryPaths paths = RepositoryLayout.FromManifest(state.ManifestPath, DateTimeOffset.Now);
        logger.SetLogPath(paths.LogPath);
        logger.Info("=== USER RESUME START ===");
        ValidateCurrentUser(state);
        if (state.NextPhase == RestorePhases.PostJoin)
        {
            logger.Info("System resume is still running; waiting for the user-profile handoff.");
            DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMinutes(2);
            do
            {
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                state = await LoadStateAsync(statePath, cancellationToken).ConfigureAwait(false);
            }
            while (state.NextPhase == RestorePhases.PostJoin && DateTimeOffset.UtcNow < deadline);
        }
        if (state.NextPhase == RestorePhases.Complete)
        {
            logger.Info("User resume is already complete.");
            await tasks.RemoveAllAsync(cancellationToken).ConfigureAwait(false);
            return;
        }
        if (state.NextPhase != RestorePhases.UserProfile)
        {
            throw new InvalidOperationException(
                $"User resume cannot start in phase '{state.NextPhase}'. The system resume did not complete the handoff within two minutes.");
        }
        string source = state.ProfileSource ?? paths.ProfilePath;
        string target = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        bool profileFilesPresent = Directory.Exists(source) &&
            Directory.EnumerateFiles(source, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            }).Any();
        if (!profileFilesPresent)
        {
            logger.Warning($"Profile source '{source}' contains no files; no user profile files will be restored.");
        }
        CopyResult result = await robocopy.CopyProfileAsync(
            source,
            target,
            state.IncludeOneDrive,
            [Path.Combine(source, RepositoryLayout.InfoFolderName)],
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            throw new IOException($"Profile restore failed with Robocopy exit code {result.ExitCode}.");
        }

        ArtifactRestoreResults artifactResults = artifacts.Restore(paths, target);
        MigrationManifest? manifest = await manifests.LoadAsync(state.ManifestPath, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<MappedDriveRestoreResult> driveResults = mappedDrives.Restore(manifest?.User.MappedDrives ?? []);
        IReadOnlyList<PrinterRestoreResult> printerResults = await printers.RestoreSharedPrintersAsync(
            manifest?.Computer.Printers ?? [],
            cancellationToken).ConfigureAwait(false);
        await WriteUserGuidanceAsync(
            target,
            manifest,
            driveResults,
            printerResults,
            artifactResults,
            profileFilesPresent,
            cancellationToken).ConfigureAwait(false);
        state.NextPhase = RestorePhases.Complete;
        state.UpdatedAt = DateTimeOffset.Now;
        await jsonFile.WriteAsync(statePath, state, cancellationToken).ConfigureAwait(false);
        await jsonFile.WriteAsync(paths.StatePath, state, cancellationToken).ConfigureAwait(false);
        await WriteSourceStateBestEffortAsync(state, cancellationToken).ConfigureAwait(false);
        await tasks.RemoveAllAsync(cancellationToken).ConfigureAwait(false);
        logger.Info("=== USER RESUME END ===");
    }

    private async Task<RestoreState> LoadStateAsync(string statePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        return await jsonFile.ReadAsync<RestoreState>(statePath, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException($"Resume state could not be read: {statePath}");
    }

    private async Task WriteSourceStateBestEffortAsync(RestoreState state, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(state.SourceStatePath))
        {
            return;
        }
        try
        {
            await jsonFile.WriteAsync(state.SourceStatePath, state, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            logger.Warning($"Unable to update source repository state '{state.SourceStatePath}': {exception.Message}");
        }
    }

    private static void ValidateCurrentUser(RestoreState state)
    {
        string expected = state.TargetDomainUser ?? state.TargetLocalUser ?? string.Empty;
        expected = expected.Split('\\').Last();
        if (!string.Equals(expected, Environment.UserName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"User resume is assigned to '{expected}', but the current user is '{Environment.UserName}'.");
        }
    }

    private static async Task WriteUserGuidanceAsync(
        string profilePath,
        MigrationManifest? manifest,
        IReadOnlyList<MappedDriveRestoreResult> driveResults,
        IReadOnlyList<PrinterRestoreResult> printerResults,
        ArtifactRestoreResults artifactResults,
        bool profileFilesPresent,
        CancellationToken cancellationToken)
    {
        string desktop = Path.Combine(profilePath, "Desktop");
        Directory.CreateDirectory(desktop);
        StringBuilder text = new();
        text.AppendLine("PC Migration - Final Technician Actions");
        text.AppendLine("========================================");
        text.AppendLine();
        text.AppendLine("Set current-user default applications in Settings > Apps > Default apps.");
        text.AppendLine($"Captured PDF ProgId: {manifest?.User.DefaultPdfProgId ?? "not captured"}");
        text.AppendLine($"Captured browser ProgId: {manifest?.User.DefaultBrowserProgId ?? "not captured"}");
        if (!profileFilesPresent)
        {
            text.AppendLine();
            text.AppendLine("ACTION REQUIRED: The gathered UserProfile folder was empty, so no desktop, document, download, or other profile files were available to restore.");
        }
        if (artifactResults.WallpaperCopied && !artifactResults.WallpaperApplied)
        {
            text.AppendLine();
            text.AppendLine("ACTION REQUIRED: The captured wallpaper file was restored, but Windows did not activate it automatically.");
        }
        if (artifactResults.BrowserExportCount > 0)
        {
            text.AppendLine();
            text.AppendLine($"Browser password exports: {artifactResults.BrowserExportCount} CSV file(s) were copied to {artifactResults.BrowserExportDirectory}.");
            text.AppendLine("These files contain sensitive data. Import them into the intended browsers, then delete the CSV files.");
        }
        if (driveResults.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Mapped drives:");
            foreach (MappedDriveRestoreResult result in driveResults)
            {
                text.AppendLine($"  {(result.Succeeded ? "OK" : "ACTION REQUIRED")} {result.DeviceId} -> {result.RemotePath}: {result.Message}");
            }
        }
        if (printerResults.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Shared printers:");
            foreach (PrinterRestoreResult result in printerResults)
            {
                text.AppendLine($"  {(result.Succeeded ? "OK" : "ACTION REQUIRED")} {result.Name}: {result.Message}");
            }
        }
        if (manifest?.Computer.Printers.Any(static printer => PrinterRestoreService.SharedConnectionName(printer).Length == 0) == true)
        {
            text.AppendLine();
            text.AppendLine("Local and TCP/IP printers were recorded in the technician report but were not installed automatically because the matching driver cannot be verified safely.");
        }
        if (manifest?.Computer.NetworkAdapters.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Captured IP settings are in the technician report. They were not applied automatically because the destination adapter identity and address availability must be verified.");
        }
        if (!string.IsNullOrWhiteSpace(manifest?.OutlookSetupAccount?.Email))
        {
            text.AppendLine();
            text.AppendLine($"Add Outlook account: {manifest.OutlookSetupAccount.Email}");
            text.AppendLine("The legacy encrypted password is intentionally not displayed because source-user DPAPI data is not portable.");
        }
        await File.WriteAllTextAsync(
            Path.Combine(desktop, "PC Migration - Final Steps.txt"),
            text.ToString(),
            new UTF8Encoding(false),
            cancellationToken).ConfigureAwait(false);
    }
}
