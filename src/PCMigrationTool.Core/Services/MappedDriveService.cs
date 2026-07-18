using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed record MappedDriveRestoreResult(string DeviceId, string RemotePath, bool Succeeded, string Message);

public sealed partial class MappedDriveService(IAppLogger logger)
{
    private const int ResourceTypeDisk = 1;
    private const int ConnectUpdateProfile = 1;
    private const int ErrorAlreadyAssigned = 85;

    [GeneratedRegex("^[A-Za-z]:$")]
    private static partial Regex DriveLetterPattern();

    public IReadOnlyList<MappedDriveRestoreResult> Restore(IEnumerable<MappedDriveInfo> mappings)
    {
        ArgumentNullException.ThrowIfNull(mappings);
        List<MappedDriveRestoreResult> results = [];
        foreach (MappedDriveInfo mapping in mappings)
        {
            string deviceId = mapping.DeviceID.Trim();
            string remotePath = mapping.ProviderName?.Trim() ?? string.Empty;
            if (!DriveLetterPattern().IsMatch(deviceId) || !remotePath.StartsWith(@"\\", StringComparison.Ordinal))
            {
                const string skipMessage = "Skipped because the captured drive letter or UNC path is invalid.";
                logger.Warning($"Mapped drive '{deviceId}' was not restored. {skipMessage}");
                results.Add(new(deviceId, remotePath, false, skipMessage));
                continue;
            }

            if (!OperatingSystem.IsWindows())
            {
                const string platformMessage = "Mapped-drive restore is supported only on Windows.";
                results.Add(new(deviceId, remotePath, false, platformMessage));
                continue;
            }

            NetResource resource = new()
            {
                Scope = 0,
                Type = ResourceTypeDisk,
                DisplayType = 0,
                Usage = 0,
                LocalName = deviceId,
                RemoteName = remotePath,
                Comment = null,
                Provider = null
            };
            int status = WNetAddConnection2(ref resource, null, null, ConnectUpdateProfile);
            bool succeeded = status is 0 or ErrorAlreadyAssigned;
            string message = status switch
            {
                0 => "Connected and made persistent.",
                ErrorAlreadyAssigned => "Drive letter is already assigned; existing mapping was retained.",
                _ => new Win32Exception(status).Message
            };
            if (succeeded)
            {
                logger.Info($"Mapped drive '{deviceId}' restored to '{remotePath}'. {message}");
            }
            else
            {
                logger.Warning($"Mapped drive '{deviceId}' could not be restored to '{remotePath}': {message}");
            }
            results.Add(new(deviceId, remotePath, succeeded, message));
        }
        return results;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string? RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(
        ref NetResource netResource,
        string? password,
        string? username,
        int flags);
}
