using System.ComponentModel;
using System.Runtime.InteropServices;
using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool.Core.Services;

public sealed class WindowsAccountService(IAppLogger logger)
{
    private const uint UserPrivilege = 1;
    private const uint UserFlags = 0x0001 | 0x10000;
    private const int Success = 0;
    private const int UserExists = 2224;
    private const int MemberExists = 1378;

    public void EnsureLocalUser(string username, string? password, bool makeAdministrator)
    {
        ValidateUsername(username);
        if (password is { Length: > 256 })
        {
            throw new ArgumentException("Password exceeds the Windows local-account limit.", nameof(password));
        }

        UserInfo1 user = new()
        {
            Name = username,
            Password = password,
            PasswordAge = 0,
            Privilege = UserPrivilege,
            HomeDirectory = null,
            Comment = "Created by PC Migration Tool",
            Flags = UserFlags,
            ScriptPath = null
        };
        int result = NetUserAdd(null, 1, ref user, out _);
        if (result == UserExists)
        {
            if (!string.IsNullOrEmpty(password))
            {
                UserInfo1003 passwordInfo = new() { Password = password };
                result = NetUserSetInfo(null, username, 1003, ref passwordInfo, out _);
                ThrowIfFailed(result, $"update local user '{username}'");
            }
            logger.Info($"Local user '{username}' already exists.");
        }
        else
        {
            ThrowIfFailed(result, $"create local user '{username}'");
            logger.Info($"Created local user '{username}'.");
        }

        AddToLocalGroup(username, "Users");
        if (makeAdministrator)
        {
            AddToLocalGroup(username, "Administrators");
        }
    }

    private void AddToLocalGroup(string username, string group)
    {
        LocalGroupMemberInfo3 member = new() { DomainAndName = username };
        int result = NetLocalGroupAddMembers(null, group, 3, ref member, 1);
        if (result is not (Success or MemberExists))
        {
            ThrowIfFailed(result, $"add '{username}' to '{group}'");
        }
        logger.Info($"Confirmed '{username}' membership in '{group}'.");
    }

    private static void ValidateUsername(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        if (username.Length > 20 || username.IndexOfAny(['\\', '/', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@', '"']) >= 0)
        {
            throw new ArgumentException("Local username is not valid.", nameof(username));
        }
    }

    private static void ThrowIfFailed(int result, string operation)
    {
        if (result != Success)
        {
            throw new Win32Exception(result, $"Unable to {operation} (NetAPI status {result}).");
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Password;
        public uint PasswordAge;
        public uint Privilege;
        [MarshalAs(UnmanagedType.LPWStr)] public string? HomeDirectory;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string? ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1003
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Password;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LocalGroupMemberInfo3
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string DomainAndName;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserAdd(string? serverName, uint level, ref UserInfo1 buffer, out uint parameterError);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(string? serverName, string username, uint level, ref UserInfo1003 buffer, out uint parameterError);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupAddMembers(string? serverName, string groupName, uint level, ref LocalGroupMemberInfo3 buffer, uint totalEntries);
}
