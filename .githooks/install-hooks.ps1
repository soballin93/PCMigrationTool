#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Installs Git hooks for PCMigrationTool
.DESCRIPTION
    Configures Git to use the custom hooks directory and sets up
    the pre-commit hook for local validation.
#>

$ErrorActionPreference = 'Stop'

Write-Host "Installing Git hooks..." -ForegroundColor Cyan

# Get the repository root
$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Host "ERROR: Not in a Git repository" -ForegroundColor Red
    exit 1
}

$hooksDir = Join-Path $repoRoot '.githooks'

if (-not (Test-Path $hooksDir)) {
    Write-Host "ERROR: Hooks directory not found at $hooksDir" -ForegroundColor Red
    exit 1
}

# Configure Git to use our custom hooks directory
Write-Host "Configuring Git hooks directory..." -ForegroundColor Yellow
git config core.hooksPath .githooks

# Make the hook executable (for Unix-like systems, harmless on Windows)
$preCommitHook = Join-Path $hooksDir 'pre-commit'
if (Test-Path $preCommitHook) {
    Write-Host "Setting execute permissions on pre-commit hook..." -ForegroundColor Yellow
    if ($IsLinux -or $IsMacOS) {
        chmod +x $preCommitHook
    }
}

Write-Host ""
Write-Host "Git hooks installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "The following hooks are now active:" -ForegroundColor Cyan
Write-Host "  - pre-commit: Validates syntax and runs PSScriptAnalyzer" -ForegroundColor Gray
Write-Host ""
Write-Host "To bypass hooks (not recommended), use: git commit --no-verify" -ForegroundColor Yellow
