using System.Text;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed class ManifestService(AtomicJsonFile jsonFile, IAppLogger logger)
{
    public Task<MigrationManifest?> LoadAsync(string path, CancellationToken cancellationToken = default) =>
        jsonFile.ReadAsync<MigrationManifest>(path, cancellationToken);

    public Task SaveAsync(string path, MigrationManifest manifest, CancellationToken cancellationToken = default) =>
        jsonFile.WriteAsync(path, manifest, cancellationToken);

    public async Task<string> WriteReportAsync(
        RepositoryPaths paths,
        MigrationManifest manifest,
        CancellationToken cancellationToken = default)
    {
        StringBuilder report = new();
        report.AppendLine($"PC Migration Technician Report - {manifest.General.ComputerName}");
        report.AppendLine($"Generated: {DateTimeOffset.Now:O}");
        report.AppendLine($"Program Version: {manifest.General.ProgramVersion}");
        report.AppendLine($"Manifest Schema: {manifest.SchemaVersion}");
        report.AppendLine();
        report.AppendLine("---- Summary ----");
        report.AppendLine($"Include OneDrive: {manifest.IncludeOneDrive}");
        report.AppendLine($"Profile copy: {FormatCopy(manifest.ProfileCopy)}");
        report.AppendLine($"Wallpaper copied: {manifest.WallpaperCopied}");
        report.AppendLine($"Outlook signatures copied: {manifest.SignaturesCopied}");
        report.AppendLine($"Wireless profiles exported: {manifest.WirelessProfilesExported}");
        report.AppendLine($"Desktop screenshots: {manifest.DesktopScreenshots.Count}");
        report.AppendLine();
        report.AppendLine("---- Computer ----");
        report.AppendLine($"Hostname: {manifest.Computer.Hostname}");
        report.AppendLine($"Domain: {manifest.Computer.DomainName} (joined: {manifest.Computer.PartOfDomain})");
        report.AppendLine($"Hardware: {manifest.Computer.Manufacturer} {manifest.Computer.Model}");
        report.AppendLine($"Serial: {manifest.Computer.SerialNumber}");
        report.AppendLine($"OS: {manifest.Computer.OperatingSystem} {manifest.Computer.OperatingSystemVersion}");
        report.AppendLine($"RAM: {manifest.Computer.PhysicalMemoryBytes / 1024d / 1024d / 1024d:F1} GB");
        report.AppendLine();
        report.AppendLine("---- Network ----");
        foreach (NetworkAdapterInfo adapter in manifest.Computer.NetworkAdapters)
        {
            report.AppendLine($"{adapter.InterfaceAlias} | {adapter.IPv4Address}/{adapter.SubnetMask} | GW {adapter.DefaultGateway} | DNS {adapter.DnsServers} | DHCP {adapter.DhcpEnabled} | MAC {adapter.MacAddress}");
        }
        report.AppendLine();
        report.AppendLine("---- Printers ----");
        foreach (PrinterInfo printer in manifest.Computer.Printers)
        {
            report.AppendLine($"{printer.Name} | Driver: {printer.DriverName} | Port: {printer.PortName}");
        }
        report.AppendLine();
        report.AppendLine("---- Installed Programs ----");
        foreach (InstalledProgramInfo program in manifest.Computer.InstalledPrograms)
        {
            report.AppendLine($"{program.Name} | Version: {program.Version} | Publisher: {program.Publisher} | Installed: {program.InstallDate}");
        }
        report.AppendLine();
        report.AppendLine("---- User ----");
        report.AppendLine($"Username: {manifest.User.Username}");
        report.AppendLine($"Office signed-in user: {manifest.User.OfficeSignedInUser}");
        report.AppendLine($"Default PDF ProgId: {manifest.User.DefaultPdfProgId}");
        report.AppendLine($"Default Browser ProgId: {manifest.User.DefaultBrowserProgId}");
        report.AppendLine("Mapped Drives:");
        foreach (MappedDriveInfo drive in manifest.User.MappedDrives)
        {
            report.AppendLine($"  {drive.DeviceID} -> {drive.ProviderName}");
        }
        report.AppendLine();
        report.AppendLine("---- Browser Exports ----");
        foreach (BrowserExportInfo browser in manifest.BrowserPasswordExports)
        {
            report.AppendLine($"{browser.DisplayName}: {(browser.Exported ? "present" : "missing")} ({browser.FileName})");
        }
        report.AppendLine();
        report.AppendLine("---- Deregistration Checklist ----");
        foreach (ChecklistItem item in manifest.DeregChecklist)
        {
            report.AppendLine($"[{(item.Completed ? 'X' : ' ')}] {item.Name} ({item.Notes})");
        }

        await File.WriteAllTextAsync(paths.ReportPath, report.ToString(), new UTF8Encoding(false), cancellationToken)
            .ConfigureAwait(false);
        logger.Info($"Technician report written: {paths.ReportPath}");
        return paths.ReportPath;
    }

    private static string FormatCopy(CopyResult? result) => result is null
        ? "skipped"
        : $"{result.Classification}, exit {result.ExitCode}, success={result.Succeeded}";
}
