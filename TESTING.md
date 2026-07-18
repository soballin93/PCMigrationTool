# Testing and Validation

## Automated Checks

Run on Windows with the .NET 10 SDK:

```powershell
dotnet restore .\PCMigrationTool.sln
dotnet build .\PCMigrationTool.sln -c Release --no-restore
dotnet test .\PCMigrationTool.sln -c Release --no-build
```

xUnit tests cover repository layout enforcement, atomic/legacy JSON loading, Robocopy exit codes and exclusions, mapped-drive validation, and shared-printer selection. The build treats compiler warnings as errors.

If `PCSwapTool.ps1` changes, also install Pester 5 and PSScriptAnalyzer and run:

```powershell
.\Invoke-ValidationSuite.ps1 -Detailed
```

## Required Windows Exercise

Changes to gather, profile copy, account setup, domain join, tasks, or resume logic require two Windows 10/11 machines or disposable VMs:

1. Build and publish on the source machine.
2. Create a uniquely named marker in the source profile.
3. Run a full gather; require a successful result JSON and Robocopy code below 8.
4. Transfer the executable and complete repository. Compare executable SHA-256 values.
5. Confirm the destination has no `dotnet` command.
6. Prepare restore and execute the cached system/user resume phases.
7. Require `NextPhase: Complete`, matching marker hashes, final guidance, and removal of both scheduled tasks.
8. Review the application log, `profile-copy.log`, manifest, and technician report.

Use the GUI for layout and elevation checks. Test reboot/logon scheduling when task registration changes; `--no-resume-tasks` is acceptable only for repeatable phase-level automation. Domain joins require a disposable domain object and a real reboot.

Browser changes require manual Chrome, Edge, Brave, Firefox, and Opera export checks as available. Network/printer changes must prove that unmatched adapters and unverifiable drivers remain untouched.
