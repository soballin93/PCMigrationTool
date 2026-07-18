using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public enum RobocopyOutcome
{
    NoChanges,
    FilesCopied,
    AdditionalFiles,
    Mismatches,
    CopyFailure
}

public static class RobocopyExitCodes
{
    public static bool IsSuccess(int exitCode) => exitCode is >= 0 and < 8;

    public static RobocopyOutcome Classify(int exitCode) => exitCode switch
    {
        < 0 => RobocopyOutcome.CopyFailure,
        0 => RobocopyOutcome.NoChanges,
        1 => RobocopyOutcome.FilesCopied,
        >= 2 and <= 3 => RobocopyOutcome.AdditionalFiles,
        >= 4 and <= 7 => RobocopyOutcome.Mismatches,
        _ => RobocopyOutcome.CopyFailure
    };
}

public sealed class RobocopyService(IProcessRunner processRunner, IAppLogger logger)
{
    private static readonly string[] BaseExclusions =
    [
        @"AppData\Local\Temp",
        @"AppData\Local\Packages",
        @"AppData\Local\ConnectedDevicesPlatform",
        @"AppData\Local\Microsoft\GameDVR",
        @"AppData\Local\Microsoft\WindowsApps",
        @"AppData\Local\Microsoft\Windows\Caches",
        @"AppData\Local\Microsoft\Windows\Explorer",
        @"AppData\Local\Microsoft\Windows\INetCache",
        @"AppData\Local\Microsoft\Windows\Notifications",
        @"AppData\Local\Microsoft\Windows\SFAP",
        @"AppData\Local\Microsoft\Windows\WebCache",
        @"AppData\Local\CrashDumps"
    ];

    private static readonly string[] BaseExcludedFiles =
    [
        "NTUSER.DAT",
        "ntuser.dat.LOG*",
        "ntuser.ini",
        "UsrClass.dat",
        "UsrClass.dat.LOG*",
        "WebCacheLock.dat"
    ];

    public async Task<CopyResult> CopyProfileAsync(
        string source,
        string destination,
        bool includeOneDrive,
        IEnumerable<string>? additionalExcludedDirectories = null,
        CancellationToken cancellationToken = default,
        Action<string>? output = null,
        bool preserveSecurity = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        if (!Directory.Exists(source))
        {
            throw new DirectoryNotFoundException($"Profile source does not exist: {source}");
        }

        Directory.CreateDirectory(destination);
        string transcriptDirectory = logger.LogPath is null
            ? Path.GetDirectoryName(destination)!
            : Path.GetDirectoryName(logger.LogPath)!;
        List<string> arguments =
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
            $"/LOG+:{Path.Combine(transcriptDirectory, "profile-copy.log")}",
            "/XF"
        ];
        arguments.AddRange(BaseExcludedFiles);

        if (preserveSecurity && !IsUncPath(source) && !IsUncPath(destination))
        {
            arguments.Add("/SEC");
        }

        IEnumerable<string> exclusions = BaseExclusions;
        if (additionalExcludedDirectories is not null)
        {
            exclusions = exclusions.Concat(additionalExcludedDirectories);
        }
        if (!includeOneDrive)
        {
            exclusions = exclusions.Concat(
                Directory.EnumerateDirectories(source, "OneDrive*", SearchOption.TopDirectoryOnly)
                    .Select(Path.GetFileName)
                    .Where(static name => !string.IsNullOrWhiteSpace(name))
                    .Select(static name => name!));
        }

        foreach (string exclusion in exclusions.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            arguments.Add("/XD");
            arguments.Add(Path.IsPathRooted(exclusion) ? exclusion : Path.Combine(source, exclusion));
        }

        DateTimeOffset startedAt = DateTimeOffset.Now;
        logger.Info($"Copying profile from '{source}' to '{destination}'.");
        ProcessResult process = await processRunner.RunAsync(
            "robocopy.exe",
            arguments,
            TimeSpan.FromHours(24),
            cancellationToken,
            output).ConfigureAwait(false);
        DateTimeOffset completedAt = DateTimeOffset.Now;

        RobocopyOutcome outcome = RobocopyExitCodes.Classify(process.ExitCode);
        if (!RobocopyExitCodes.IsSuccess(process.ExitCode))
        {
            logger.Error($"Robocopy failed with exit code {process.ExitCode}.");
        }
        else if (outcome == RobocopyOutcome.Mismatches)
        {
            logger.Warning($"Robocopy completed with mismatch status {process.ExitCode}; review the log.");
        }
        else
        {
            logger.Info($"Robocopy completed successfully with status {process.ExitCode} ({outcome}).");
        }

        return new CopyResult
        {
            ExitCode = process.ExitCode,
            Succeeded = RobocopyExitCodes.IsSuccess(process.ExitCode),
            Classification = outcome.ToString(),
            Source = source,
            Destination = destination,
            StartedAt = startedAt,
            CompletedAt = completedAt
        };
    }

    private static bool IsUncPath(string path) => path.StartsWith(@"\\", StringComparison.Ordinal);
}
