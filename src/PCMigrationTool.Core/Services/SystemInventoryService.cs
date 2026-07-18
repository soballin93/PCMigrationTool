using System.Management;
using System.Net.NetworkInformation;
using System.Numerics;
using Microsoft.Win32;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed class SystemInventoryService(IProcessRunner processRunner, IAppLogger logger)
{
    public async Task<(GeneralInfo General, ComputerInfo Computer, UserInfo User)> CollectAsync(
        string programVersion,
        CancellationToken cancellationToken = default)
    {
        logger.Info("Collecting general system information.");
        GeneralInfo general = new()
        {
            ProgramVersion = programVersion,
            CollectedAt = DateTimeOffset.Now,
            UserDomain = Environment.UserDomainName,
            UserName = Environment.UserName,
            ComputerName = Environment.MachineName
        };

        ComputerInfo computer = await CollectComputerAsync(cancellationToken).ConfigureAwait(false);
        UserInfo user = CollectUser();
        return (general, computer, user);
    }

    private async Task<ComputerInfo> CollectComputerAsync(CancellationToken cancellationToken)
    {
        ComputerInfo computer = new() { Hostname = Environment.MachineName };
        TryQuerySingle("SELECT Domain, PartOfDomain, Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem", item =>
        {
            computer.DomainName = AsString(item["Domain"]);
            computer.PartOfDomain = AsBoolean(item["PartOfDomain"]);
            computer.Manufacturer = AsString(item["Manufacturer"]);
            computer.Model = AsString(item["Model"]);
            computer.PhysicalMemoryBytes = AsInt64(item["TotalPhysicalMemory"]);
        });
        TryQuerySingle("SELECT SerialNumber FROM Win32_BIOS", item =>
            computer.SerialNumber = AsString(item["SerialNumber"]));
        TryQuerySingle("SELECT Caption, Version FROM Win32_OperatingSystem", item =>
        {
            computer.OperatingSystem = AsString(item["Caption"]);
            computer.OperatingSystemVersion = AsString(item["Version"]);
        });

        computer.NetworkAdapters = CollectNetworkAdapters();
        computer.Printers = CollectPrinters();
        computer.InstalledPrograms = CollectInstalledPrograms();
        computer.WirelessNetworks = await GetWirelessProfileNamesAsync(cancellationToken).ConfigureAwait(false);
        return computer;
    }

    private List<NetworkAdapterInfo> CollectNetworkAdapters()
    {
        List<NetworkAdapterInfo> adapters = [];
        TryQueryMany(
            "SELECT Description, InterfaceIndex, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, MACAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
            item =>
            {
                string[] addresses = AsStringArray(item["IPAddress"]);
                string[] subnets = AsStringArray(item["IPSubnet"]);
                int ipv4Index = Array.FindIndex(addresses, static address =>
                    System.Net.IPAddress.TryParse(address, out System.Net.IPAddress? parsed) &&
                    parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                if (ipv4Index < 0)
                {
                    return;
                }

                string ipv4 = addresses[ipv4Index];
                string subnet = ipv4Index < subnets.Length ? subnets[ipv4Index] : string.Empty;
                adapters.Add(new NetworkAdapterInfo
                {
                    InterfaceAlias = AsString(item["Description"]),
                    InterfaceIndex = AsInt32(item["InterfaceIndex"]),
                    IPv4Address = ipv4,
                    SubnetMask = PrefixLength(subnet),
                    DefaultGateway = AsStringArray(item["DefaultIPGateway"]).FirstOrDefault() ?? string.Empty,
                    DnsServers = string.Join(',', AsStringArray(item["DNSServerSearchOrder"])),
                    MacAddress = NormalizeMac(AsString(item["MACAddress"])),
                    DhcpEnabled = AsBoolean(item["DHCPEnabled"])
                });
            });
        return adapters.OrderBy(static adapter => adapter.InterfaceIndex).ToList();
    }

    private List<PrinterInfo> CollectPrinters()
    {
        List<PrinterInfo> printers = [];
        TryQueryMany("SELECT Name, DriverName, PortName FROM Win32_Printer", item =>
            printers.Add(new PrinterInfo
            {
                Name = AsString(item["Name"]),
                DriverName = AsString(item["DriverName"]),
                PortName = AsString(item["PortName"])
            }));
        return printers.OrderBy(static printer => printer.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private List<InstalledProgramInfo> CollectInstalledPrograms()
    {
        List<InstalledProgramInfo> programs = [];
        ReadUninstallHive(RegistryHive.LocalMachine, RegistryView.Registry64, programs);
        ReadUninstallHive(RegistryHive.LocalMachine, RegistryView.Registry32, programs);
        ReadUninstallHive(RegistryHive.CurrentUser, RegistryView.Default, programs);

        return programs
            .GroupBy(
                static program => $"{program.Name}\0{program.Version}\0{program.InstallDir}",
                StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderBy(static program => program.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void ReadUninstallHive(RegistryHive hive, RegistryView view, List<InstalledProgramInfo> programs)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
            using RegistryKey? uninstall = baseKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstall is null)
            {
                return;
            }

            foreach (string subKeyName in uninstall.GetSubKeyNames())
            {
                using RegistryKey? item = uninstall.OpenSubKey(subKeyName);
                string? displayName = item?.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(displayName) || Convert.ToInt32(item?.GetValue("SystemComponent") ?? 0) == 1)
                {
                    continue;
                }

                string? releaseType = item?.GetValue("ReleaseType") as string;
                if (releaseType?.Contains("Update", StringComparison.OrdinalIgnoreCase) == true)
                {
                    continue;
                }

                programs.Add(new InstalledProgramInfo
                {
                    Name = displayName,
                    Version = item?.GetValue("DisplayVersion") as string,
                    InstallDate = NormalizeInstallDate(item?.GetValue("InstallDate")?.ToString()),
                    InstallDir = item?.GetValue("InstallLocation") as string,
                    Publisher = item?.GetValue("Publisher") as string,
                    UninstallStr = item?.GetValue("UninstallString") as string
                });
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.Warning($"Unable to read {hive}/{view} uninstall inventory: {exception.Message}");
        }
    }

    private UserInfo CollectUser()
    {
        logger.Info("Collecting current-user settings.");
        return new UserInfo
        {
            Username = Environment.UserName,
            MappedDrives = CollectMappedDrives(),
            OfficeSignedInUser = ReadOfficeIdentity(),
            DefaultPdfProgId = ReadProgId(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoiceLatest",
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice"),
            DefaultBrowserProgId = ReadProgId(
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoiceLatest",
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice")
        };
    }

    private List<MappedDriveInfo> CollectMappedDrives()
    {
        Dictionary<string, MappedDriveInfo> drives = new(StringComparer.OrdinalIgnoreCase);
        foreach (DriveInfo drive in DriveInfo.GetDrives().Where(static drive => drive.DriveType == DriveType.Network))
        {
            drives[drive.Name.TrimEnd('\\')] = new MappedDriveInfo
            {
                DeviceID = drive.Name.TrimEnd('\\'),
                VolumeName = TryGetVolumeName(drive)
            };
        }

        try
        {
            using RegistryKey? network = Registry.CurrentUser.OpenSubKey("Network");
            if (network is not null)
            {
                foreach (string letter in network.GetSubKeyNames())
                {
                    using RegistryKey? mapping = network.OpenSubKey(letter);
                    string id = letter.EndsWith(':') ? letter : letter + ":";
                    drives[id] = new MappedDriveInfo
                    {
                        DeviceID = id,
                        ProviderName = mapping?.GetValue("RemotePath") as string,
                        VolumeName = drives.GetValueOrDefault(id)?.VolumeName
                    };
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.Warning($"Unable to enumerate persistent mapped drives: {exception.Message}");
        }

        return drives.Values.OrderBy(static drive => drive.DeviceID, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<List<string>> GetWirelessProfileNamesAsync(CancellationToken cancellationToken)
    {
        try
        {
            ProcessResult result = await processRunner.RunAsync(
                "netsh.exe",
                ["wlan", "show", "profiles"],
                TimeSpan.FromSeconds(30),
                cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return [];
            }

            return result.StandardOutput
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(static line => line.Split(':', 2))
                .Where(static parts => parts.Length == 2 && parts[0].Contains("Profile", StringComparison.OrdinalIgnoreCase))
                .Select(static parts => parts[1].Trim())
                .Where(static value => value.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception exception) when (exception is IOException or TimeoutException)
        {
            logger.Warning($"Unable to enumerate wireless profiles: {exception.Message}");
            return [];
        }
    }

    private string? ReadOfficeIdentity()
    {
        try
        {
            using RegistryKey? identities = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Office\16.0\Common\Identity\Identities");
            if (identities is null)
            {
                return null;
            }

            foreach (string identityName in identities.GetSubKeyNames())
            {
                using RegistryKey? identity = identities.OpenSubKey(identityName);
                if (identity?.GetValue("EmailAddress") is string email && !string.IsNullOrWhiteSpace(email))
                {
                    return email;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.Warning($"Unable to read Office identity: {exception.Message}");
        }

        return null;
    }

    private static string? ReadProgId(params string[] candidatePaths)
    {
        foreach (string path in candidatePaths)
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(path);
            if (key?.GetValue("ProgId") is string progId && !string.IsNullOrWhiteSpace(progId))
            {
                return progId;
            }
            if (key?.GetValue(null) is string defaultProgId && !string.IsNullOrWhiteSpace(defaultProgId))
            {
                return defaultProgId;
            }
        }

        return null;
    }

    private void TryQuerySingle(string query, Action<ManagementBaseObject> projector)
    {
        TryQueryMany(query, item =>
        {
            projector(item);
            throw new StopEnumerationException();
        });
    }

    private void TryQueryMany(string query, Action<ManagementBaseObject> projector)
    {
        try
        {
            using ManagementObjectSearcher searcher = new(query);
            using ManagementObjectCollection results = searcher.Get();
            foreach (ManagementBaseObject item in results)
            {
                try
                {
                    projector(item);
                }
                catch (StopEnumerationException)
                {
                    break;
                }
            }
        }
        catch (ManagementException exception)
        {
            logger.Warning($"WMI query failed: {exception.Message}");
        }
    }

    private static string AsString(object? value) => value?.ToString()?.Trim() ?? string.Empty;
    private static bool AsBoolean(object? value) => value is not null && Convert.ToBoolean(value);
    private static int AsInt32(object? value) => value is null ? 0 : Convert.ToInt32(value);
    private static long AsInt64(object? value) => value is null ? 0 : Convert.ToInt64(value);
    private static string[] AsStringArray(object? value) => value is string[] values ? values : [];
    private static string NormalizeMac(string value) => value.Replace(':', '-').ToUpperInvariant();

    private static int PrefixLength(string subnet)
    {
        if (int.TryParse(subnet, out int prefix))
        {
            return prefix;
        }

        if (!System.Net.IPAddress.TryParse(subnet, out System.Net.IPAddress? mask))
        {
            return 0;
        }

        return mask.GetAddressBytes().Sum(static value => BitOperations.PopCount(value));
    }

    private static string? NormalizeInstallDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTime.TryParseExact(value, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out DateTime parsed)
            ? parsed.ToString("yyyy-MM-dd")
            : value;
    }

    private static string? TryGetVolumeName(DriveInfo drive)
    {
        try
        {
            return drive.IsReady ? drive.VolumeLabel : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private sealed class StopEnumerationException : Exception
    {
    }
}
