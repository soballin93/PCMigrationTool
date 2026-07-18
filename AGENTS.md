# Repository Guidelines

## Project Structure & Module Organization

The supported application is the .NET 10 WinForms rewrite. `src/PCMigrationTool/` contains the executable, GUI, command-line host, and administrator manifest. Platform logic, JSON models, logging, inventory, gather, restore, and resume services live in `src/PCMigrationTool.Core/`. xUnit tests are under `tests/PCMigrationTool.Core.Tests/`. `PCSwapTool.ps1` and `tests/PCSwapTool.Tests.ps1` are the retained legacy implementation and regression suite. Generated releases belong in `artifacts/` and must not be committed.

## Build, Test, and Development Commands

Run these commands from Windows with the .NET 10 SDK:

```powershell
dotnet restore .\PCMigrationTool.sln
dotnet build .\PCMigrationTool.sln -c Release --no-restore
dotnet test .\PCMigrationTool.sln -c Release --no-build
.\scripts\Build-Release.ps1
```

The release script tests and publishes a self-contained, single-file `win-x64` executable. Launch `artifacts\publish\PCMigrationTool.exe` as administrator. Use `Invoke-Pester .\tests\PCSwapTool.Tests.ps1` only when changing the legacy script.

## Coding Style & Naming Conventions

Use four-space indentation, file-scoped namespaces, nullable reference types, and implicit usings. Treat warnings as errors. Name public types and members `PascalCase`, locals and parameters `camelCase`, and asynchronous methods with an `Async` suffix. Keep Windows API calls isolated in services and pass process arguments with `ProcessStartInfo.ArgumentList`; never build command strings containing credentials. Persist JSON through `AtomicJsonFile` and log operational decisions through `IAppLogger`.

## Testing Guidelines

Name tests `*Tests.cs` and use behavior-focused xUnit names such as `Create_PreservesRequiredRepositoryShape`. Add unit coverage for schema compatibility, path validation, exit-code handling, and safe restore selection. Gather/profile/GUI/resume changes also require a Windows 10/11 source-to-destination test. Verify the destination without an installed .NET runtime.

## Commit & Pull Request Guidelines

Use short imperative commit subjects, for example `Harden profile restore exclusions`. PRs must separate gather, restore, resume, and UI impacts; list automated and manual Windows tests; call out schema or security changes; and include screenshots for visible UI changes. Never commit manifests, state files, logs, screenshots, browser exports, copied profiles, or credentials.
