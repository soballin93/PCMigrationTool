using System.Text.Json;
using System.Text.Json.Serialization;

namespace PCMigrationTool.Core.Models;

public sealed class MigrationManifest
{
    public const string CurrentSchemaVersion = "1.1";

    public string SchemaVersion { get; set; } = CurrentSchemaVersion;
    public string Mode { get; set; } = "Gather";
    public GeneralInfo General { get; set; } = new();
    public ComputerInfo Computer { get; set; } = new();
    public UserInfo User { get; set; } = new();
    public bool IncludeOneDrive { get; set; }
    public string CollectedBy { get; set; } = string.Empty;
    public DateTimeOffset CollectedAt { get; set; } = DateTimeOffset.Now;
    public bool ChromeCsv { get; set; }
    public List<BrowserExportInfo> BrowserPasswordExports { get; set; } = [];
    public bool WallpaperCopied { get; set; }
    public bool SignaturesCopied { get; set; }
    public List<ChecklistItem> DeregChecklist { get; set; } = [];
    public bool WirelessProfilesExported { get; set; }
    public List<string> WirelessNetworks { get; set; } = [];
    public LegacyOutlookSetupAccount? OutlookSetupAccount { get; set; }
    public List<string> DesktopScreenshots { get; set; } = [];
    public CopyResult? ProfileCopy { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public sealed class GeneralInfo
{
    public string ProgramVersion { get; set; } = string.Empty;
    public DateTimeOffset CollectedAt { get; set; } = DateTimeOffset.Now;
    public string UserDomain { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
}

public sealed class ComputerInfo
{
    public string Hostname { get; set; } = string.Empty;
    public string DomainName { get; set; } = string.Empty;
    public bool PartOfDomain { get; set; }
    public string Manufacturer { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string OperatingSystemVersion { get; set; } = string.Empty;
    public long PhysicalMemoryBytes { get; set; }
    public List<NetworkAdapterInfo> NetworkAdapters { get; set; } = [];
    public List<PrinterInfo> Printers { get; set; } = [];
    public List<InstalledProgramInfo> InstalledPrograms { get; set; } = [];
    public List<string> WirelessNetworks { get; set; } = [];
}

public sealed class NetworkAdapterInfo
{
    public string InterfaceAlias { get; set; } = string.Empty;
    public int InterfaceIndex { get; set; }
    public string IPv4Address { get; set; } = string.Empty;
    public int SubnetMask { get; set; }
    public string DefaultGateway { get; set; } = string.Empty;
    public string DnsServers { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public bool DhcpEnabled { get; set; }
}

public sealed class PrinterInfo
{
    public string Name { get; set; } = string.Empty;
    public string DriverName { get; set; } = string.Empty;
    public string PortName { get; set; } = string.Empty;
}

public sealed class InstalledProgramInfo
{
    public string Name { get; set; } = string.Empty;
    public string? Version { get; set; }
    public string? InstallDate { get; set; }
    public string? InstallDir { get; set; }
    public string? Publisher { get; set; }
    public string? UninstallStr { get; set; }
}

public sealed class UserInfo
{
    public string Username { get; set; } = string.Empty;
    public List<MappedDriveInfo> MappedDrives { get; set; } = [];
    public List<OutlookAccountInfo> OutlookAccounts { get; set; } = [];
    public string? OfficeSignedInUser { get; set; }
    public string? DefaultPdfProgId { get; set; }
    public string? DefaultBrowserProgId { get; set; }
}

public sealed class MappedDriveInfo
{
    public string DeviceID { get; set; } = string.Empty;
    public string? ProviderName { get; set; }
    public string? VolumeName { get; set; }
}

public sealed class OutlookAccountInfo
{
    public string DisplayName { get; set; } = string.Empty;
    public string? SmtpAddress { get; set; }
    public string? AccountType { get; set; }
}

public sealed class BrowserExportInfo
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool Exported { get; set; }
    public string FileName { get; set; } = string.Empty;
}

public sealed class BrowserInfo
{
    public required string Name { get; init; }
    public required string DisplayName { get; init; }
    public required string ExecutablePath { get; init; }
    public required string PasswordUrl { get; init; }
    public required string ExportFileName { get; init; }
}

public sealed class ChecklistItem
{
    public string Name { get; set; } = string.Empty;
    public bool Completed { get; set; }
    public string Notes { get; set; } = string.Empty;
}

public sealed class LegacyOutlookSetupAccount
{
    public string Email { get; set; } = string.Empty;
    [JsonIgnore]
    public string Password { get; set; } = string.Empty;
}

public sealed class CopyResult
{
    public int ExitCode { get; set; }
    public bool Succeeded { get; set; }
    public string Classification { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset CompletedAt { get; set; }
}
