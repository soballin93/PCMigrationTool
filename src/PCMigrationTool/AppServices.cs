using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool;

internal sealed class AppServices
{
    public AppServices()
    {
        Logger = new AppLogger();
        Json = new AtomicJsonFile();
        ProcessRunner = new ProcessRunner(Logger);
        PowerShell = new PowerShellRunner(ProcessRunner);
        Browser = new BrowserService(Logger);
        Artifacts = new ArtifactService(Logger);
        WirelessProfiles = new WirelessProfileService(ProcessRunner, Logger);
        Inventory = new SystemInventoryService(ProcessRunner, Logger);
        Robocopy = new RobocopyService(ProcessRunner, Logger);
        Manifests = new ManifestService(Json, Logger);
        ResumeTasks = new ResumeTaskService(PowerShell, Logger);
        Accounts = new WindowsAccountService(Logger);
        DomainJoin = new DomainJoinService(Logger);
        RepositoryStaging = new RepositoryStagingService(ProcessRunner, Logger);
        MappedDrives = new MappedDriveService(Logger);
        Printers = new PrinterRestoreService(ProcessRunner, Logger);
        Gather = new GatherService(
            Inventory,
            Browser,
            Artifacts,
            WirelessProfiles,
            Robocopy,
            Manifests,
            Json,
            Logger);
        Restore = new RestoreService(
            Manifests,
            Json,
            Accounts,
            DomainJoin,
            ResumeTasks,
            RepositoryStaging,
            PowerShell,
            Logger);
        Resume = new ResumeService(
            Json,
            Manifests,
            WirelessProfiles,
            Robocopy,
            Artifacts,
            MappedDrives,
            Printers,
            ResumeTasks,
            Logger);
    }

    public AppLogger Logger { get; }
    public AtomicJsonFile Json { get; }
    public ProcessRunner ProcessRunner { get; }
    public PowerShellRunner PowerShell { get; }
    public BrowserService Browser { get; }
    public ArtifactService Artifacts { get; }
    public WirelessProfileService WirelessProfiles { get; }
    public SystemInventoryService Inventory { get; }
    public RobocopyService Robocopy { get; }
    public ManifestService Manifests { get; }
    public ResumeTaskService ResumeTasks { get; }
    public WindowsAccountService Accounts { get; }
    public DomainJoinService DomainJoin { get; }
    public RepositoryStagingService RepositoryStaging { get; }
    public MappedDriveService MappedDrives { get; }
    public PrinterRestoreService Printers { get; }
    public GatherService Gather { get; }
    public RestoreService Restore { get; }
    public ResumeService Resume { get; }
}
