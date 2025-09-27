# PCMigrationTool Contributor Guidelines

These instructions apply to the entire repository.

## Repository overview
- `PCSwapTool_v0.5.20.ps1` is the primary PowerShell script. It implements a WinForms GUI that drives the gather/restore/resume workflow, writes a technician report and manifest, and orchestrates resume logic via `state.json`.
- `BouncyCastle.Crypto.dll` and `System.Data.SQLite.dll` are bundled dependencies used for Chrome password export. Keep their versions in sync with what the script expects.

## PowerShell coding standards
1. **Preserve strict-mode compatibility**
   - `Set-StrictMode -Version Latest` is enabled. Guard property access (`$obj.PSObject.Properties[...]`) and null-check results before use.
   - Treat registry values, COM calls, and external processes as fallible. Wrap in `try/catch` and surface failures via `Write-Log` rather than allowing unhandled exceptions to bubble into the UI.

2. **Logging discipline**
   - Always call `Write-Log` with named parameters (`-Message`, `-Level`). Only fall back to `Write-Host` in the existing catch blocks that already do so.
   - Log user-facing operations (file copies, downloads, resume scheduling, etc.) to keep the technician report trustworthy.

3. **Versioning & changelog**
   - When you change behavior, update **all** version markers together: the comment banner at the top, `$ProgramVersion`, and any changelog bullet you append under `.CHANGELOG` in the header.
   - Changelog entries are reverse-chronological (latest first) and include the version, concise bullet points, and an ISO-formatted date.

4. **Manifest/report schema**
   - If you capture new data, update both `Build-Manifest` *and* `Write-Report` so the manifest, technician report, and downstream restore logic stay aligned.
   - Maintain backwards compatibility for `state.json` and manifest files. When adding properties, default them defensively during load (`if ($manifest.PSObject.Properties['NewProp']) { ... }`).

5. **State & resume logic**
   - Resume phases depend on `state.json` and the optional `-Manifest` argument. When persisting new data for resume, extend the `$state` hashtable written in the restore click handler and consume it in both `$Resume` and `$ResumeUser` blocks.
   - Keep `New-RunOnceResume` and `Register-UserResumeTaskEx` updated if command-line arguments change. They must always pass the manifest path when available.

6. **Path handling**
   - Use `Join-Path`, `Split-Path`, and helper functions (`Set-SwapInfoRoot`, `Get-SwapInfoRoot`, etc.) instead of manual string concatenation. Always validate technician-provided paths with `Test-Path` before using them.
   - Repository artifacts must remain under `<DEST>\<HOST>_<DATE>\PC_SWAP_INFO`. Do not introduce ad-hoc folders outside that structure.

7. **External dependencies**
   - Load supporting DLLs via `Get-ToolResourcePath`. If you add a new static dependency, commit it under the repository root and ensure `Get-ToolResourcePath` can discover it (local path, working directory, or dependency cache). Avoid adding installers or MSI packages.
   - Network downloads must go through `Invoke-DownloadToolResource` so the script honors the `PCSwapToolResourceBaseUrl` override.

8. **GUI conventions**
   - Instantiate WinForms controls with explicit size/position via `SetBounds` (matching existing style) and register event handlers with script blocks. Keep new controls localized to the appropriate tab (`$tabGather` or `$tabRestore`).
   - When adding technician options, ensure their states map to script parameters (`$PSBoundParameters`) so command-line usage remains consistent.
   - Update log viewers by calling `Add-LogSubscriber` if you add new areas that need live log output.

9. **Robocopy usage**
   - Continue using `/COPY:DAT` and `/DCOPY:DAT`, adding `/SEC` only for local NTFS sources. Respect the existing exclusion lists and OneDrive toggle semantics.

## Testing expectations
- Primary validation must occur on Windows 10/11 with Windows PowerShell 5.1. At minimum, launch the script via `powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\PCSwapTool_v0.5.20.ps1` and exercise the gather and restore tabs relevant to your change.
- If you modify Chrome password export, confirm that both `System.Data.SQLite.dll` and `BouncyCastle.Crypto.dll` load successfully and that the technician prompt flow still works.
- When practical, run `pwsh -NoProfile -Command "Import-Module PSScriptAnalyzer; Invoke-ScriptAnalyzer -Path .\PCSwapTool_v0.5.20.ps1"` to catch linting issues. Document any skipped checks in your PR notes.

## Documentation & housekeeping
- Keep inline comments succinct and factual. Update tooltip or message-box text when changing technician workflows.
- Do not commit generated artifacts (logs, manifests, Chrome CSVs, copied files). Only source files and vetted dependencies belong in version control.
- When updating the UI or workflows, refresh any technician guidance shown in message boxes so expectations match the new behavior.

## Pull request notes
- Summaries should call out gather/restore/resume changes separately to aid technician review.
- List any manual Windows tests performed (e.g., gather-only run, full restore with resume).
