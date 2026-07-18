using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool.Core.Services;

public sealed record CachedApplication(string ExecutablePath, string StatePath);

public sealed class ResumeTaskService(PowerShellRunner powerShell, IAppLogger logger)
{
    public const string SystemTaskName = "PCMigrationTool-SystemResume";
    public const string UserTaskName = "PCMigrationTool-UserResume";

    public CachedApplication CacheApplication()
    {
        string? source = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(source) || !File.Exists(source))
        {
            throw new InvalidOperationException("The running executable path could not be resolved.");
        }

        string cacheDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCMigrationTool");
        Directory.CreateDirectory(cacheDirectory);
        string target = Path.Combine(cacheDirectory, "PCMigrationTool.exe");
        if (!string.Equals(Path.GetFullPath(source), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(source, target, true);
        }

        logger.Info($"Cached executable for resume: {target}");
        return new CachedApplication(target, Path.Combine(cacheDirectory, "resume-state.json"));
    }

    public async Task RegisterAsync(
        CachedApplication application,
        string targetUser,
        string repositoryStatePath,
        CancellationToken cancellationToken = default)
    {
        string executable = PowerShellRunner.QuoteLiteral(application.ExecutablePath);
        string state = PowerShellRunner.QuoteLiteral(application.StatePath);
        string user = PowerShellRunner.QuoteLiteral(targetUser);
        string repositoryState = PowerShellRunner.QuoteLiteral(repositoryStatePath);
        string systemArguments = PowerShellRunner.QuoteLiteral($"--resume-system --state \"{application.StatePath}\"");
        string userArguments = PowerShellRunner.QuoteLiteral($"--resume-user --state \"{application.StatePath}\"");
        string script = $$"""
            $ErrorActionPreference = 'Stop'
            $systemAction = New-ScheduledTaskAction -Execute {{executable}} -Argument {{systemArguments}}
            $systemTrigger = New-ScheduledTaskTrigger -AtStartup
            $systemPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

            $userAction = New-ScheduledTaskAction -Execute {{executable}} -Argument {{userArguments}}
            $userTrigger = New-ScheduledTaskTrigger -AtLogOn -User {{user}}
            $userPrincipal = New-ScheduledTaskPrincipal -UserId {{user}} -LogonType Interactive -RunLevel Highest

            if (-not (Test-Path -LiteralPath {{state}})) { throw 'Resume state was not written.' }
            $sid = ([System.Security.Principal.NTAccount]{{user}}).Translate([System.Security.Principal.SecurityIdentifier])
            foreach ($stateFile in @({{state}}, {{repositoryState}})) {
                if ($stateFile.StartsWith('\\')) { continue }
                $acl = Get-Acl -LiteralPath $stateFile
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'Modify', 'Allow')
                $acl.SetAccessRule($rule)
                Set-Acl -LiteralPath $stateFile -AclObject $acl
            }
            if (-not ({{repositoryState}}).StartsWith('\\')) {
                $repositoryRoot = Split-Path -Parent {{repositoryState}}
                $repositoryAcl = Get-Acl -LiteralPath $repositoryRoot
                $readRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid,
                    'Modify',
                    'ContainerInherit,ObjectInherit',
                    'None',
                    'Allow')
                $repositoryAcl.SetAccessRule($readRule)
                Set-Acl -LiteralPath $repositoryRoot -AclObject $repositoryAcl
            }

            Register-ScheduledTask -TaskName '{{SystemTaskName}}' -Action $systemAction -Trigger $systemTrigger -Principal $systemPrincipal -Force | Out-Null
            Register-ScheduledTask -TaskName '{{UserTaskName}}' -Action $userAction -Trigger $userTrigger -Principal $userPrincipal -Force | Out-Null

            $scheduler = New-Object -ComObject 'Schedule.Service'
            $scheduler.Connect()
            $registeredUserTask = $scheduler.GetFolder('\').GetTask('{{UserTaskName}}')
            $taskSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGXSD;;;$($sid.Value))"
            $registeredUserTask.SetSecurityDescriptor($taskSddl, 0)
            """;
        ProcessResult result = await powerShell.RunAsync(script, TimeSpan.FromMinutes(2), cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            await RemoveAllAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("Unable to register resume tasks: " + result.StandardError);
        }
        logger.Info($"Registered system and user resume tasks for '{targetUser}'.");
    }

    public Task RemoveSystemTaskAsync(CancellationToken cancellationToken = default) =>
        RemoveTasksAsync([SystemTaskName], cancellationToken);

    public Task RemoveAllAsync(CancellationToken cancellationToken = default) =>
        RemoveTasksAsync([SystemTaskName, UserTaskName], cancellationToken);

    private async Task RemoveTasksAsync(IReadOnlyList<string> names, CancellationToken cancellationToken)
    {
        string taskNames = string.Join(", ", names.Select(PowerShellRunner.QuoteLiteral));
        string script = $$"""
            $ErrorActionPreference = 'Stop'
            $failures = @()
            foreach ($taskName in @({{taskNames}})) {
                try {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                }
                catch {
                    if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
                        $failures += "${taskName}: $($_.Exception.Message)"
                    }
                }
            }
            if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
            """;
        ProcessResult result = await powerShell.RunAsync(script, TimeSpan.FromMinutes(1), cancellationToken)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            string message = string.IsNullOrWhiteSpace(result.StandardError)
                ? $"PowerShell returned exit code {result.ExitCode}."
                : result.StandardError.Trim();
            throw new InvalidOperationException("Unable to remove resume task(s): " + message);
        }
    }
}
