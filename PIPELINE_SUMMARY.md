# Pipeline Summary

GitHub Actions validates both the supported .NET rewrite and the retained PowerShell implementation on Windows.

The native job restores the .NET 10 solution, builds with warnings treated as errors, runs xUnit tests, publishes a self-contained single-file `win-x64` executable, and uploads that executable as a workflow artifact. The legacy job runs PowerShell syntax checks, PSScriptAnalyzer, and Pester. A separate informational security scan applies PowerShell security rules.

For a local release, run:

```powershell
.\scripts\Build-Release.ps1
```

This produces the standalone executable, a versioned ZIP containing the executable and operator documentation, and a SHA-256 checksum under `artifacts\`.

CI is necessary but not sufficient for migration workflow changes. Gather, restore, account/domain, or resume changes require the two-machine Windows procedure in [TESTING.md](TESTING.md).
