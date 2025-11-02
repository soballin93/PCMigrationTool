#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs the complete validation suite for PCMigrationTool
.DESCRIPTION
    Executes syntax validation, PSScriptAnalyzer linting, and Pester tests.
    This script simulates what the CI pipeline will run, allowing developers
    to validate their changes locally before committing.
.PARAMETER SkipTests
    Skip Pester tests (only run syntax and linting)
.PARAMETER SkipLinting
    Skip PSScriptAnalyzer (only run syntax and tests)
.PARAMETER Detailed
    Show detailed output from all checks
.EXAMPLE
    .\Invoke-ValidationSuite.ps1
    Runs all validation checks
.EXAMPLE
    .\Invoke-ValidationSuite.ps1 -Detailed
    Runs all checks with verbose output
.EXAMPLE
    .\Invoke-ValidationSuite.ps1 -SkipTests
    Only runs syntax and linting checks
#>

[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipLinting,
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "       PCMigrationTool Validation Suite" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$overallSuccess = $true
$results = @{
    Syntax = $null
    Linting = $null
    Tests = $null
}

# ============================================================================
# Syntax Validation
# ============================================================================

Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
Write-Host " Syntax Validation" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
Write-Host ""

$scripts = Get-ChildItem -Path . -Filter *.ps1 -Recurse |
    Where-Object { $_.FullName -notmatch '\\(node_modules|\.git|\.vscode)\\' }

$syntaxErrors = @()

foreach ($script in $scripts) {
    $relativePath = $script.FullName.Replace("$PWD\", "")
    Write-Host "  Checking $relativePath..." -NoNewline -ForegroundColor Gray

    try {
        $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
        $parseErrors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$parseErrors)

        if ($parseErrors) {
            Write-Host " FAILED" -ForegroundColor Red
            $syntaxErrors += [PSCustomObject]@{
                File = $relativePath
                Errors = $parseErrors
            }
        } else {
            Write-Host " PASSED" -ForegroundColor Green
        }
    } catch {
        Write-Host " ERROR: $_" -ForegroundColor Red
        $syntaxErrors += [PSCustomObject]@{
            File = $relativePath
            Errors = @(@{ Message = $_.Exception.Message })
        }
    }
}

Write-Host ""

if ($syntaxErrors.Count -gt 0) {
    $results.Syntax = "FAILED"
    $overallSuccess = $false
    Write-Host "[X] Syntax validation FAILED:" -ForegroundColor Red
    foreach ($err in $syntaxErrors) {
        Write-Host "   $($err.File):" -ForegroundColor Yellow
        foreach ($e in $err.Errors) {
            Write-Host "     - Line $($e.Token.StartLine): $($e.Message)" -ForegroundColor Red
        }
    }
} else {
    $results.Syntax = "PASSED"
    Write-Host "[OK] All scripts passed syntax validation ($($scripts.Count) files checked)" -ForegroundColor Green
}

Write-Host ""

# ============================================================================
# PSScriptAnalyzer Linting
# ============================================================================

if (-not $SkipLinting) {
    Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " PSScriptAnalyzer Linting" -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ""

    if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
        $settingsPath = Join-Path $PSScriptRoot '.vscode\PSScriptAnalyzerSettings.psd1'

        try {
            if (Test-Path $settingsPath) {
                $lintResults = Invoke-ScriptAnalyzer -Path . -Recurse -Settings $settingsPath -ErrorAction Stop
            } else {
                Write-Host "  Warning: PSScriptAnalyzerSettings.psd1 not found, using defaults" -ForegroundColor Yellow
                $lintResults = Invoke-ScriptAnalyzer -Path . -Recurse -ErrorAction Stop
            }

            $errors = $lintResults | Where-Object Severity -eq 'Error'
            $warnings = $lintResults | Where-Object Severity -eq 'Warning'
            $info = $lintResults | Where-Object Severity -eq 'Information'

            if ($Detailed -and $lintResults) {
                $lintResults | Format-Table File, Line, Severity, RuleName, Message -AutoSize
            }

            Write-Host ""
            Write-Host "  Summary:" -ForegroundColor Cyan
            Write-Host "    Errors: $($errors.Count)" -ForegroundColor $(if ($errors.Count -gt 0) { 'Red' } else { 'Gray' })
            Write-Host "    Warnings: $($warnings.Count)" -ForegroundColor $(if ($warnings.Count -gt 0) { 'Yellow' } else { 'Gray' })
            Write-Host "    Info: $($info.Count)" -ForegroundColor Gray

            if ($errors.Count -gt 0) {
                $results.Linting = "FAILED"
                $overallSuccess = $false
                Write-Host ""
                Write-Host "[X] Linting FAILED - errors must be fixed:" -ForegroundColor Red
                $errors | ForEach-Object {
                    Write-Host "   $($_.ScriptName):$($_.Line) - $($_.Message)" -ForegroundColor Red
                }
            } elseif ($warnings.Count -gt 0) {
                $results.Linting = "PASSED (with warnings)"
                Write-Host ""
                Write-Host "[!] Linting PASSED with warnings (consider fixing):" -ForegroundColor Yellow
                if (-not $Detailed) {
                    $warnings | Select-Object -First 5 | ForEach-Object {
                        Write-Host "   $($_.ScriptName):$($_.Line) - $($_.Message)" -ForegroundColor Yellow
                    }
                    if ($warnings.Count -gt 5) {
                        Write-Host "   ... and $($warnings.Count - 5) more warnings" -ForegroundColor Yellow
                    }
                }
            } else {
                $results.Linting = "PASSED"
                Write-Host ""
                Write-Host "[OK] All linting checks passed!" -ForegroundColor Green
            }
        } catch {
            $results.Linting = "ERROR"
            Write-Host ""
            Write-Host "[X] Error running PSScriptAnalyzer: $_" -ForegroundColor Red
        }
    } else {
        $results.Linting = "SKIPPED"
        Write-Host "  PSScriptAnalyzer not installed - skipping" -ForegroundColor Yellow
        Write-Host "  Install with: Install-Module -Name PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor Yellow
    }

    Write-Host ""
}

# ============================================================================
# Pester Tests
# ============================================================================

if (-not $SkipTests) {
    Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " Pester Tests" -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ""

    if (Get-Module -ListAvailable -Name Pester | Where-Object Version -ge '5.0') {
        if (Test-Path './tests') {
            try {
                $config = New-PesterConfiguration
                $config.Run.Path = './tests'
                $config.Run.Exit = $false
                $config.Output.Verbosity = if ($Detailed) { 'Detailed' } else { 'Normal' }

                $testResults = Invoke-Pester -Configuration $config

                Write-Host ""
                Write-Host "  Test Summary:" -ForegroundColor Cyan
                Write-Host "    Total: $($testResults.TotalCount)" -ForegroundColor Gray
                Write-Host "    Passed: $($testResults.PassedCount)" -ForegroundColor Green
                Write-Host "    Failed: $($testResults.FailedCount)" -ForegroundColor $(if ($testResults.FailedCount -gt 0) { 'Red' } else { 'Gray' })
                Write-Host "    Skipped: $($testResults.SkippedCount)" -ForegroundColor Gray

                if ($testResults.FailedCount -gt 0) {
                    $results.Tests = "FAILED"
                    $overallSuccess = $false
                    Write-Host ""
                    Write-Host "[X] Tests FAILED" -ForegroundColor Red
                } else {
                    $results.Tests = "PASSED"
                    Write-Host ""
                    Write-Host "[OK] All tests passed!" -ForegroundColor Green
                }
            } catch {
                $results.Tests = "ERROR"
                $overallSuccess = $false
                Write-Host ""
                Write-Host "[X] Error running tests: $_" -ForegroundColor Red
            }
        } else {
            $results.Tests = "NO TESTS"
            Write-Host "  No tests directory found" -ForegroundColor Yellow
            Write-Host "  Create ./tests directory and add *.Tests.ps1 files" -ForegroundColor Yellow
        }
    } else {
        $results.Tests = "SKIPPED"
        Write-Host "  Pester 5.x not installed - skipping" -ForegroundColor Yellow
        Write-Host "  Install with: Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck" -ForegroundColor Yellow
    }

    Write-Host ""
}

# ============================================================================
# Final Summary
# ============================================================================

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                    Validation Summary" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "  Syntax Validation: " -NoNewline -ForegroundColor Gray
switch ($results.Syntax) {
    "PASSED" { Write-Host "[OK] PASSED" -ForegroundColor Green }
    "FAILED" { Write-Host "[X] FAILED" -ForegroundColor Red }
}

if (-not $SkipLinting) {
    Write-Host "  Linting:           " -NoNewline -ForegroundColor Gray
    switch ($results.Linting) {
        "PASSED" { Write-Host "[OK] PASSED" -ForegroundColor Green }
        "PASSED (with warnings)" { Write-Host "[!] PASSED (with warnings)" -ForegroundColor Yellow }
        "FAILED" { Write-Host "[X] FAILED" -ForegroundColor Red }
        "SKIPPED" { Write-Host "[-] SKIPPED" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[X] ERROR" -ForegroundColor Red }
    }
}

if (-not $SkipTests) {
    Write-Host "  Tests:             " -NoNewline -ForegroundColor Gray
    switch ($results.Tests) {
        "PASSED" { Write-Host "[OK] PASSED" -ForegroundColor Green }
        "FAILED" { Write-Host "[X] FAILED" -ForegroundColor Red }
        "NO TESTS" { Write-Host "[-] NO TESTS" -ForegroundColor Yellow }
        "SKIPPED" { Write-Host "[-] SKIPPED" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[X] ERROR" -ForegroundColor Red }
    }
}

Write-Host ""

if ($overallSuccess) {
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "[OK] ALL VALIDATION CHECKS PASSED!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "[X] VALIDATION FAILED - Please fix the issues above" -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    exit 1
}
