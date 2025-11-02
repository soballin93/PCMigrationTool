# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PCMigrationTool is a Windows PowerShell-based WinForms GUI tool for migrating user data and settings between Windows 10/11 machines. The primary script (`PCSwapTool_v0.5.33.ps1`) implements a two-phase workflow:
1. **Gather phase**: Collects user data, settings, and preferences from a source machine, producing a manifest and technician report
2. **Restore phase**: Applies gathered data to a target machine, with scheduled resume tasks for system and user-context operations

## Key Architecture

### Core Components

- **Main Script**: `PCSwapTool_v0.5.XX.ps1` is a monolithic PowerShell script with three primary sections:
  - GUI setup and event handlers (WinForms UI with two tabs: gather and restore)
  - Helper functions for file operations, logging, registry access, and external process orchestration
  - Resume logic that executes via scheduled tasks during Windows startup and user logon

- **Data Artifacts**: The script creates a structured output under `<DESTINATION>\<HOSTNAME>_<DATE>\PC_SWAP_INFO/`:
  - `manifest.json`: Machine-readable inventory of gathered data and restoration paths
  - `technician_report.html`: Human-readable summary of migration status and operations
  - `state.json`: Persisted state for resume phase recovery (tracks which operations completed)
  - Data folders: `Users/`, `Desktop/`, `Documents/`, `Chrome/`, etc.

- **Resume Phases**:
  - System-context tasks run via `HKEY_LOCAL_MACHINE\...\Run` (via `New-RunOnceResume`)
  - User-context tasks run via Scheduled Tasks at user logon (via `Register-UserResumeTaskEx`)
  - Both phases consume the manifest and state.json to determine what to restore

- **External Dependencies**:
  - `BouncyCastle.Crypto.dll` and `System.Data.SQLite.dll`: Used for decrypting Chrome passwords
  - Loaded dynamically via `Get-ToolResourcePath` helper function
  - Network downloads routed through `Invoke-DownloadToolResource` to respect URL overrides

### Data Flow

1. **Gather**:
   - User selects source machine folders and options via GUI
   - Script copies user profile folders, desktop, documents, downloads
   - Registry keys are exported (default apps, network drives, mapped drives, etc.)
   - Chrome passwords are decrypted (BouncyCastle + System.Data.SQLite) and exported
   - Manifest and technician report are written before GUI confirms completion

2. **Restore**:
   - User loads manifest from previous gather operation
   - Script copies data to target machine and schedules resume tasks
   - System-context resume runs at next boot (registry, network drives, default apps)
   - User-context resume runs at user logon (profile data, wallpaper, Explorer refresh)

## Critical Implementation Details

### Strict Mode & Error Handling

The script runs under `Set-StrictMode -Version Latest`. This means:
- Always guard property access: use `$obj.PSObject.Properties['PropName']` instead of `$obj.PropName` when unsure
- Null-check all external calls (registry, WMI, COM) before dereferencing
- Wrap registry access and COM calls in `try/catch` blocks
- Surface failures via `Write-Log` rather than allowing exceptions to propagate to the UI

### Logging & Telemetry

- Always use `Write-Log -Message "..." -Level "Info"/"Warning"/"Error"` for user-facing operations
- Only use `Write-Host` in existing catch blocks that already do so
- Log all file copies, downloads, resume scheduling operations to build an accurate technician report
- The log viewer (`Add-LogSubscriber`) is used to display live output in the UI

### Manifest & State Management

**Manifest** (written during gather):
- Captures paths, registry keys, Chrome passwords, user profile data, etc.
- Must be kept in sync with `Build-Manifest` and `Write-Report` functions
- Used during restore to locate and apply gathered data
- Backwards compatibility required: when adding properties, use defensive checks like `if ($manifest.PSObject.Properties['NewProp'])`

**State** (persisted during restore):
- Tracks which operations completed (for resume recovery)
- Written in the restore click handler and consumed in both `$Resume` and `$ResumeUser` blocks
- Must be updated when persisting new data for resume operations

### Resume Task Registration

Two functions handle scheduling:
- **`New-RunOnceResume`**: Schedules system-context resume via registry Run key
- **`Register-UserResumeTaskEx`**: Schedules user-context resume via Windows Task Scheduler

Both must be updated if command-line arguments change or new manifest properties are added. They always pass the manifest path when available.

### Path Handling

- **Always use `Join-Path`, `Split-Path`, and helper functions** like `Set-SwapInfoRoot`/`Get-SwapInfoRoot` for path operations
- **Validate technician-provided paths** with `Test-Path` before use
- **Repository artifacts must stay under** `<DEST>\<HOST>_<DATE>\PC_SWAP_INFO` — do not introduce ad-hoc folder structures

### Chrome Password Export

The script decrypts Chrome passwords using:
1. Load `System.Data.SQLite.dll` and `BouncyCastle.Crypto.dll`
2. Query the Chrome "Login Data" SQLite database
3. Decrypt using AES-GCM (for secrets with "vXX" prefix) or DPAPI
4. Export to CSV if any credentials decrypt successfully; skip file creation if none do
5. Fallback to technician-guided manual export via `chrome://settings/passwords` if automatic export fails

Key considerations:
- AES-GCM decryption requires 32-byte keys (do not splat individual bytes to BouncyCastle)
- DPAPI fallback: try CurrentUser scope first, then LocalMachine for service/system profiles
- Respect the `ProtectedData` type initialization flag under StrictMode

### Robocopy Usage

- Continue using `/COPY:DAT /DCOPY:DAT` for most operations
- Add `/SEC` only for local NTFS sources (not network drives)
- Respect existing exclusion lists and OneDrive toggle semantics
- Network drives should not use `/SEC`

### GUI Conventions

- Instantiate WinForms controls with explicit size/position via `SetBounds`
- Register event handlers using script blocks
- Localize new controls to the appropriate tab (`$tabGather` or `$tabRestore`)
- Ensure technician options map to script parameters so command-line usage remains consistent
- Update log viewers by calling `Add-LogSubscriber` for new areas

## Development Workflow

### Common Commands

**Run the main script**:
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\PCSwapTool_v0.5.33.ps1
```

**Lint with PSScriptAnalyzer** (optional, document any skipped checks):
```powershell
pwsh -NoProfile -Command "Import-Module PSScriptAnalyzer; Invoke-ScriptAnalyzer -Path .\PCSwapTool_v0.5.33.ps1"
```

### Testing Requirements

- **Primary validation platform**: Windows 10/11 with Windows PowerShell 5.1
- **Minimal test**: Launch the script and exercise the gather and restore tabs relevant to your change
- **Chrome password export changes**: Verify both DLL files load and the technician prompt flow works
- **Resume logic changes**: Test both system-context and user-context resume phases (system reboot, user logon)
- **Registry/COM changes**: Ensure strict mode compatibility and proper error handling

### Version Control

When changing behavior:
1. Update **all** version markers together:
   - Comment banner at the top of the script
   - `$ProgramVersion` variable
   - Changelog entry under `.CHANGELOG` in the header comment block

2. Changelog format (reverse-chronological):
   - Version number (e.g., `0.5.34`)
   - Concise bullet points describing the change
   - ISO-formatted date (e.g., `2025-11-01`)

## Repository Guidelines

Refer to `AGENTS.md` for detailed PowerShell coding standards, GUI conventions, and state management requirements. Key points:
- Preserve strict-mode compatibility at all times
- Use helper functions for path operations and dependency loading
- Keep manifest/state/resume logic synchronized across their three locations
- Maintain backwards compatibility for saved manifest and state.json files
- Test on Windows PowerShell 5.1 (PowerShell Desktop) as the primary runtime
