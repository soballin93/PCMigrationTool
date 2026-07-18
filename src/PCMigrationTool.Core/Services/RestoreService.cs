using System.Text.RegularExpressions;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed record DomainJoinOptions(
    string DomainName,
    string? OrganizationalUnit,
    string JoinAccount,
    string JoinPassword,
    string TargetDomainUser);

public sealed record RestoreOptions(
    string ManifestPath,
    string? RequestedHostname,
    string? ProfileSource,
    string? LocalUsername,
    string? LocalPassword,
    bool MakeLocalAdministrator,
    DomainJoinOptions? DomainJoin,
    bool RegisterResumeTasks);

public sealed record RestorePreparation(
    RestoreState State,
    bool RebootRequired,
    string CachedExecutable,
    string CachedStatePath);

public sealed partial class RestoreService(
    ManifestService manifests,
    AtomicJsonFile jsonFile,
    WindowsAccountService accounts,
    DomainJoinService domainJoin,
    ResumeTaskService resumeTasks,
    RepositoryStagingService repositoryStaging,
    PowerShellRunner powerShell,
    IAppLogger logger)
{
    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$")]
    private static partial Regex HostnamePattern();

    public async Task<RestorePreparation> PrepareAsync(
        RestoreOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ManifestPath);
        if (!File.Exists(options.ManifestPath))
        {
            throw new FileNotFoundException("Manifest was not found.", options.ManifestPath);
        }

        RepositoryPaths sourcePaths = RepositoryLayout.FromManifest(options.ManifestPath, DateTimeOffset.Now);
        logger.SetLogPath(sourcePaths.LogPath);
        MigrationManifest manifest = await manifests.LoadAsync(options.ManifestPath, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException("Manifest could not be parsed.");
        ValidateManifest(manifest);
        string sourceProfile = ResolveProfileSource(sourcePaths, options.ProfileSource);
        StagedRepository staged = await repositoryStaging.StageIfNeededAsync(
            sourcePaths,
            sourceProfile,
            cancellationToken).ConfigureAwait(false);
        RepositoryPaths paths = staged.Paths;
        if (staged.WasStaged)
        {
            logger.SetLogPath(paths.LogPath);
        }

        bool rebootRequired = false;
        string targetUser;
        string? targetLocalUser = null;
        string? targetDomainUser = null;
        if (options.DomainJoin is not null)
        {
            domainJoin.Join(
                options.DomainJoin.DomainName,
                options.DomainJoin.OrganizationalUnit,
                options.DomainJoin.JoinAccount,
                options.DomainJoin.JoinPassword);
            targetDomainUser = options.DomainJoin.TargetDomainUser;
            targetUser = QualifyDomainUser(options.DomainJoin.DomainName, targetDomainUser);
            rebootRequired = true;
        }
        else
        {
            targetLocalUser = options.LocalUsername
                ?? throw new ArgumentException("A local target user is required when no domain join is requested.");
            accounts.EnsureLocalUser(targetLocalUser, options.LocalPassword, options.MakeLocalAdministrator);
            targetUser = targetLocalUser;
        }

        if (!string.IsNullOrWhiteSpace(options.RequestedHostname) &&
            !string.Equals(options.RequestedHostname, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
        {
            ValidateHostname(options.RequestedHostname);
            string name = PowerShellRunner.QuoteLiteral(options.RequestedHostname);
            ProcessResult rename = await powerShell.RunAsync(
                $"Rename-Computer -NewName {name} -Force -ErrorAction Stop",
                TimeSpan.FromMinutes(2),
                cancellationToken).ConfigureAwait(false);
            if (!rename.Succeeded)
            {
                throw new InvalidOperationException("Unable to rename computer: " + rename.StandardError);
            }
            rebootRequired = true;
            logger.Info($"Computer rename to '{options.RequestedHostname}' is pending reboot.");
        }

        CachedApplication cached = resumeTasks.CacheApplication();
        RestoreState state = new()
        {
            ManifestPath = paths.ManifestPath,
            ProfileSource = staged.ProfileSource,
            SourceStatePath = staged.SourceStatePath,
            IncludeOneDrive = manifest.IncludeOneDrive,
            TargetLocalUser = targetLocalUser,
            TargetDomainUser = targetDomainUser,
            RequestedHostname = options.RequestedHostname,
            NextPhase = RestorePhases.PostJoin,
            UpdatedAt = DateTimeOffset.Now
        };
        await jsonFile.WriteAsync(paths.StatePath, state, cancellationToken).ConfigureAwait(false);
        await WriteSourceStateBestEffortAsync(staged.SourceStatePath, state, cancellationToken).ConfigureAwait(false);
        await jsonFile.WriteAsync(cached.StatePath, state, cancellationToken).ConfigureAwait(false);
        if (options.RegisterResumeTasks)
        {
            await resumeTasks.RegisterAsync(cached, targetUser, paths.StatePath, cancellationToken).ConfigureAwait(false);
        }

        logger.Info("Restore preparation completed.");
        return new RestorePreparation(state, rebootRequired, cached.ExecutablePath, cached.StatePath);
    }

    private async Task WriteSourceStateBestEffortAsync(
        string? sourceStatePath,
        RestoreState state,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sourceStatePath))
        {
            return;
        }
        try
        {
            await jsonFile.WriteAsync(sourceStatePath, state, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            logger.Warning($"Unable to update source repository state '{sourceStatePath}': {exception.Message}");
        }
    }

    private static void ValidateManifest(MigrationManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(manifest.Computer.Hostname) || string.IsNullOrWhiteSpace(manifest.General.ComputerName))
        {
            throw new InvalidDataException("Manifest is missing required computer identity fields.");
        }
        if (manifest.SchemaVersion is not ("1.0" or MigrationManifest.CurrentSchemaVersion))
        {
            throw new InvalidDataException($"Unsupported manifest schema '{manifest.SchemaVersion}'.");
        }
    }

    private static void ValidateHostname(string hostname)
    {
        if (!HostnamePattern().IsMatch(hostname))
        {
            throw new ArgumentException("Hostname must be 1-15 characters using letters, numbers, and interior hyphens.", nameof(hostname));
        }
    }

    private static string QualifyDomainUser(string domainName, string username) =>
        username.Contains('\\') ? username : $"{domainName}\\{username}";

    private static string ResolveProfileSource(RepositoryPaths paths, string? requested)
    {
        if (!string.IsNullOrWhiteSpace(requested))
        {
            string full = Path.GetFullPath(requested);
            if (!Directory.Exists(full))
            {
                throw new DirectoryNotFoundException($"Profile source does not exist: {full}");
            }
            return Directory.Exists(Path.Combine(full, RepositoryLayout.InfoFolderName, "UserProfile"))
                ? Path.Combine(full, RepositoryLayout.InfoFolderName, "UserProfile")
                : full;
        }

        return Directory.Exists(paths.ProfilePath) ? paths.ProfilePath : paths.HostRoot;
    }
}
