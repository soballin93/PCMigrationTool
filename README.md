# PC Migration Tool

PC Migration Tool is a portable Windows application for moving a user environment from one Windows 10/11 PC to another. It gathers an auditable migration repository, prepares the destination, and resumes system- and user-context work safely after a reboot.

The release is a self-contained `win-x64` executable. The destination does not need .NET, PowerShell modules, an installer, or administrative setup beyond approving the normal elevation prompt.

## What It Migrates

- User-profile files, with OneDrive content optional
- Wallpaper and Outlook signatures
- Wi-Fi profiles
- Persistent mapped drives that use valid UNC paths
- Shared printers with verifiable `\\server\share` connections
- Browser password CSVs exported by the technician, delivered to `Documents\PC Migration Browser Exports`
- Inventory for applications, printers, adapters, Office identity, default apps, and Outlook accounts

Windows IP configuration, local/TCP printer drivers, default applications, and legacy Outlook passwords are recorded for technician action instead of being applied blindly. Source-user DPAPI secrets cannot be safely decrypted on a different PC.
Browser CSVs contain plaintext credentials; import them into the intended browsers and delete them after verification.

## Technician Workflow

1. Run `PCMigrationTool.exe` as administrator on the source PC.
2. On **Gather**, choose an existing destination and prepare browser exports if required.
3. Move the resulting `<HOST>_<DATE>\PC_SWAP_INFO` repository to the destination PC.
4. Run the same executable on the destination, open **Restore**, and select `manifest.json`.
5. Choose the target local or domain user and prepare the restore. Reboot when prompted.
6. Sign in as the selected target user. The cached executable resumes from `%ProgramData%\PCMigrationTool` and removes its scheduled tasks after completion. Repositories opened from a UNC path are staged beneath `%ProgramData%\PCMigrationTool\Repository` first, so resume does not depend on network-share access.

Every run writes an application log, a Robocopy transcript, `manifest.json`, and a technician report inside `PC_SWAP_INFO`. State files are written atomically and schema `1.0` manifests remain readable.

## Build and Test

Install the .NET 10 SDK on a Windows build machine, then run:

```powershell
dotnet restore .\PCMigrationTool.sln
dotnet build .\PCMigrationTool.sln -c Release --no-restore
dotnet test .\PCMigrationTool.sln -c Release --no-build
.\scripts\Build-Release.ps1
```

The packaged executable, ZIP, and SHA-256 checksum are written under `artifacts\`.

## Automation

The executable also supports `--gather`, `--prepare-restore`, `--resume-system`, and `--resume-user`. Pass `--result-file <path>` to receive an atomic JSON result with the exit code, status, message, and primary artifact. See [DEVELOPMENT.md](DEVELOPMENT.md) for examples and architecture details.

`PCSwapTool.ps1` remains in the repository as the legacy PowerShell implementation; new production work should target the .NET solution.
