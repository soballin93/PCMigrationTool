namespace PCMigrationTool.Core.Services;

public sealed record RepositoryPaths(
    string HostRoot,
    string InfoRoot,
    string ManifestPath,
    string StatePath,
    string ChecklistPath,
    string ProfilePath,
    string BrowserExportsPath,
    string WirelessProfilesPath,
    string ScreenshotsPath,
    string LogPath,
    string ReportPath);

public static class RepositoryLayout
{
    public const string InfoFolderName = "PC_SWAP_INFO";

    public static RepositoryPaths Create(string destinationBase, string computerName, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationBase);
        ArgumentException.ThrowIfNullOrWhiteSpace(computerName);

        string safeComputerName = ValidateComputerName(computerName);
        string basePath = Path.GetFullPath(destinationBase);
        string hostRoot = Path.Combine(basePath, $"{safeComputerName}_{now:dd-MM-yyyy}");
        string infoRoot = Path.Combine(hostRoot, InfoFolderName);
        string stamp = now.ToString("yyyy-MM-dd_HH-mm-ss");
        return new RepositoryPaths(
            hostRoot,
            infoRoot,
            Path.Combine(infoRoot, "manifest.json"),
            Path.Combine(infoRoot, "state.json"),
            Path.Combine(infoRoot, "deregistration-checklist.json"),
            Path.Combine(infoRoot, "UserProfile"),
            Path.Combine(infoRoot, "Browser_Exports"),
            Path.Combine(infoRoot, "WirelessProfiles"),
            Path.Combine(infoRoot, "Screenshots"),
            Path.Combine(infoRoot, $"pcmigration_{stamp}.log"),
            Path.Combine(infoRoot, $"technician_report_{stamp}.txt"));
    }

    public static RepositoryPaths FromManifest(string manifestPath, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        string fullManifestPath = Path.GetFullPath(manifestPath);
        string infoRoot = Path.GetDirectoryName(fullManifestPath)
            ?? throw new ArgumentException("Manifest path has no parent directory.", nameof(manifestPath));
        if (!string.Equals(Path.GetFileName(infoRoot), InfoFolderName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"The manifest must be inside a {InfoFolderName} folder.");
        }

        string hostRoot = Directory.GetParent(infoRoot)?.FullName
            ?? throw new InvalidDataException("The PC_SWAP_INFO folder has no host parent folder.");
        string stamp = now.ToString("yyyy-MM-dd_HH-mm-ss");
        return new RepositoryPaths(
            hostRoot,
            infoRoot,
            fullManifestPath,
            Path.Combine(infoRoot, "state.json"),
            Path.Combine(infoRoot, "deregistration-checklist.json"),
            Path.Combine(infoRoot, "UserProfile"),
            Path.Combine(infoRoot, "Browser_Exports"),
            Path.Combine(infoRoot, "WirelessProfiles"),
            Path.Combine(infoRoot, "Screenshots"),
            Path.Combine(infoRoot, $"pcmigration_{stamp}.log"),
            Path.Combine(infoRoot, $"technician_report_{stamp}.txt"));
    }

    public static void EnsureDirectories(RepositoryPaths paths)
    {
        Directory.CreateDirectory(paths.HostRoot);
        Directory.CreateDirectory(paths.InfoRoot);
        Directory.CreateDirectory(paths.ProfilePath);
        Directory.CreateDirectory(paths.BrowserExportsPath);
        Directory.CreateDirectory(paths.ScreenshotsPath);
    }

    private static string ValidateComputerName(string computerName)
    {
        string trimmed = computerName.Trim();
        if (trimmed.Length is < 1 or > 63 || trimmed.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException("Computer name is not valid for a repository folder.", nameof(computerName));
        }

        return trimmed;
    }
}
