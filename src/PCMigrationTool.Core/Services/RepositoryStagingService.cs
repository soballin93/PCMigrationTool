using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool.Core.Services;

public sealed record StagedRepository(
    RepositoryPaths Paths,
    string ProfileSource,
    bool WasStaged,
    string? SourceStatePath);

public sealed class RepositoryStagingService(IProcessRunner processRunner, IAppLogger logger)
{
    public async Task<StagedRepository> StageIfNeededAsync(
        RepositoryPaths sourcePaths,
        string profileSource,
        CancellationToken cancellationToken = default)
    {
        if (!RequiresStaging(sourcePaths.ManifestPath, profileSource))
        {
            return new(sourcePaths, profileSource, false, null);
        }

        string cacheRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCMigrationTool",
            "Repository");
        string hostFolder = Path.GetFileName(sourcePaths.HostRoot);
        string stagedHostRoot = Path.Combine(cacheRoot, hostFolder);
        string stagedInfoRoot = Path.Combine(stagedHostRoot, RepositoryLayout.InfoFolderName);
        if (Directory.Exists(stagedHostRoot))
        {
            Directory.Delete(stagedHostRoot, true);
        }
        Directory.CreateDirectory(stagedInfoRoot);

        logger.Info($"Staging network migration repository locally from '{sourcePaths.InfoRoot}'.");
        await CopyDirectoryAsync(sourcePaths.InfoRoot, stagedInfoRoot, cacheRoot, cancellationToken)
            .ConfigureAwait(false);

        string stagedProfile = MapProfilePath(sourcePaths.InfoRoot, stagedInfoRoot, profileSource);
        if (string.Equals(stagedProfile, Path.Combine(stagedInfoRoot, "UserProfile"), StringComparison.OrdinalIgnoreCase) &&
            !IsWithin(sourcePaths.InfoRoot, profileSource))
        {
            Directory.CreateDirectory(stagedProfile);
            await CopyDirectoryAsync(profileSource, stagedProfile, cacheRoot, cancellationToken).ConfigureAwait(false);
        }

        string stagedManifest = Path.Combine(stagedInfoRoot, "manifest.json");
        if (!File.Exists(stagedManifest))
        {
            throw new InvalidDataException("The locally staged repository does not contain manifest.json.");
        }
        RepositoryPaths stagedPaths = RepositoryLayout.FromManifest(stagedManifest, DateTimeOffset.Now);
        logger.Info($"Network repository staged locally: {stagedInfoRoot}");
        return new(stagedPaths, stagedProfile, true, sourcePaths.StatePath);
    }

    public static bool RequiresStaging(string manifestPath, string profileSource) =>
        IsUncPath(manifestPath) || IsUncPath(profileSource);

    private async Task CopyDirectoryAsync(
        string source,
        string destination,
        string logDirectory,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(source))
        {
            throw new DirectoryNotFoundException($"Repository source does not exist: {source}");
        }
        Directory.CreateDirectory(destination);
        ProcessResult result = await processRunner.RunAsync(
            "robocopy.exe",
            [
                source,
                destination,
                "/E",
                "/R:2",
                "/W:2",
                "/XJ",
                "/COPY:DAT",
                "/DCOPY:DAT",
                "/NP",
                "/TEE",
                $"/LOG+:{Path.Combine(logDirectory, "repository-staging.log")}"
            ],
            TimeSpan.FromHours(24),
            cancellationToken).ConfigureAwait(false);
        if (!RobocopyExitCodes.IsSuccess(result.ExitCode))
        {
            throw new IOException($"Repository staging failed with Robocopy exit code {result.ExitCode}.");
        }
    }

    private static string MapProfilePath(string sourceInfoRoot, string stagedInfoRoot, string profileSource)
    {
        if (!IsWithin(sourceInfoRoot, profileSource))
        {
            return Path.Combine(stagedInfoRoot, "UserProfile");
        }
        string relative = Path.GetRelativePath(sourceInfoRoot, profileSource);
        return Path.Combine(stagedInfoRoot, relative);
    }

    private static bool IsWithin(string parent, string candidate)
    {
        string relative = Path.GetRelativePath(
            Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            Path.GetFullPath(candidate));
        return relative != ".." &&
            !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
            !Path.IsPathRooted(relative);
    }

    private static bool IsUncPath(string path) => path.StartsWith(@"\\", StringComparison.Ordinal);
}
