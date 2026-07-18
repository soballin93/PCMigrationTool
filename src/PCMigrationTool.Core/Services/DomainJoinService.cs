using System.ComponentModel;
using System.Runtime.InteropServices;
using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool.Core.Services;

public sealed class DomainJoinService(IAppLogger logger)
{
    private const int Success = 0;
    private const JoinOptions Options = JoinOptions.JoinDomain | JoinOptions.AccountCreate | JoinOptions.DomainJoinIfJoined;

    public void Join(string domainName, string? organizationalUnit, string accountName, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainName);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        int result = NetJoinDomain(
            null,
            domainName,
            string.IsNullOrWhiteSpace(organizationalUnit) ? null : organizationalUnit,
            accountName,
            password,
            Options);
        if (result != Success)
        {
            throw new Win32Exception(result, $"Domain join failed with status {result}.");
        }

        logger.Info($"Domain join to '{domainName}' completed; reboot is required.");
    }

    [Flags]
    private enum JoinOptions : uint
    {
        JoinDomain = 0x00000001,
        AccountCreate = 0x00000002,
        DomainJoinIfJoined = 0x00000020
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetJoinDomain(
        string? server,
        string domain,
        string? accountOrganizationalUnit,
        string account,
        string password,
        JoinOptions options);
}
