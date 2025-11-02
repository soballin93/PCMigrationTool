#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Pre-commit hook for PCMigrationTool (PowerShell version)
.DESCRIPTION
    Runs syntax validation and PSScriptAnalyzer before allowing commits.
    This is the Windows-friendly version that doesn't require Git Bash.
#>

$ErrorActionPreference = 'Stop'

Write-Host "Running pre-commit validation..." -ForegroundColor Cyan

# Get the list of staged PowerShell files
$stagedFiles = git diff --cached --name-only --diff-filter=ACM | Where-Object { $_ -match '\.ps1$' }

if (-not $stagedFiles) {
    Write-Host "No PowerShell files staged for commit." -ForegroundColor Gray
    exit 0
}

Write-Host "Validating $($stagedFiles.Count) PowerShell file(s)..." -ForegroundColor Cyan

$hasErrors = $false

# Syntax validation
Write-Host "`nChecking syntax..." -ForegroundColor Yellow
foreach ($file in $stagedFiles) {
    if (Test-Path $file) {
        Write-Host "  Checking $file..." -ForegroundColor Gray
        $content = Get-Content -Path $file -Raw
        $parseErrors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$parseErrors)

        if ($parseErrors) {
            Write-Host "    FAILED: Syntax errors found" -ForegroundColor Red
            $parseErrors | ForEach-Object {
                Write-Host "      Line $($_.Token.StartLine): $($_.Message)" -ForegroundColor Red
            }
            $hasErrors = $true
        } else {
            Write-Host "    PASSED" -ForegroundColor Green
        }
    }
}

# PSScriptAnalyzer validation
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    Write-Host "`nRunning PSScriptAnalyzer..." -ForegroundColor Yellow

    $settingsPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '.vscode') 'PSScriptAnalyzerSettings.psd1'

    foreach ($file in $stagedFiles) {
        if (Test-Path $file) {
            Write-Host "  Analyzing $file..." -ForegroundColor Gray

            if (Test-Path $settingsPath) {
                $results = Invoke-ScriptAnalyzer -Path $file -Settings $settingsPath
            } else {
                $results = Invoke-ScriptAnalyzer -Path $file
            }

            $errors = $results | Where-Object Severity -eq 'Error'
            $warnings = $results | Where-Object Severity -eq 'Warning'

            if ($errors) {
                Write-Host "    FAILED: $($errors.Count) error(s) found" -ForegroundColor Red
                $errors | ForEach-Object {
                    Write-Host "      Line $($_.Line): $($_.Message)" -ForegroundColor Red
                }
                $hasErrors = $true
            } elseif ($warnings) {
                Write-Host "    WARNING: $($warnings.Count) warning(s) found" -ForegroundColor Yellow
                $warnings | ForEach-Object {
                    Write-Host "      Line $($_.Line): $($_.Message)" -ForegroundColor Yellow
                }
                # Warnings don't block commits
            } else {
                Write-Host "    PASSED" -ForegroundColor Green
            }
        }
    }
} else {
    Write-Host "`nPSScriptAnalyzer not installed - skipping linting" -ForegroundColor Yellow
    Write-Host "Install with: Install-Module -Name PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor Yellow
}

# Summary
Write-Host ""
if ($hasErrors) {
    Write-Host "PRE-COMMIT FAILED: Please fix the errors above before committing." -ForegroundColor Red
    Write-Host "To bypass this check (not recommended), use: git commit --no-verify" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "PRE-COMMIT PASSED: All checks successful!" -ForegroundColor Green
    exit 0
}
