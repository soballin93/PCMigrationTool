# Testing & Validation Quick Start

This document provides a quick reference for running tests and validation locally.

## Quick Commands

### Run Everything
```powershell
.\Invoke-ValidationSuite.ps1
```

### Run Specific Checks
```powershell
# Syntax and linting only (fast)
.\Invoke-ValidationSuite.ps1 -SkipTests

# Syntax and tests only
.\Invoke-ValidationSuite.ps1 -SkipLinting

# With detailed output
.\Invoke-ValidationSuite.ps1 -Detailed
```

### Run Tests Only
```powershell
# Run all tests
Invoke-Pester ./tests

# Run with detailed output
Invoke-Pester ./tests -Output Detailed

# Run specific test file
Invoke-Pester ./tests/PCSwapTool.Tests.ps1
```

### Run Linting Only
```powershell
# Analyze all scripts
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\.vscode\PSScriptAnalyzerSettings.psd1

# Analyze specific file
Invoke-ScriptAnalyzer -Path .\PCSwapTool.ps1 -Settings .\.vscode\PSScriptAnalyzerSettings.psd1
```

## Setup (One-Time)

### Install Required Modules
```powershell
# PSScriptAnalyzer for linting
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

# Pester for testing (requires v5.0+)
Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

### Install Git Hooks
```powershell
.\.githooks\install-hooks.ps1
```

This enables automatic validation before each commit.

## What Gets Checked

| Check | Tool | Purpose | Blocks Commit? |
|-------|------|---------|----------------|
| **Syntax** | PowerShell Parser | Ensures code parses without errors | Yes |
| **Linting** | PSScriptAnalyzer | Checks style, best practices, security | Errors only |
| **Tests** | Pester | Validates functionality | Yes |

## Understanding Results

### Syntax Validation
- **PASSED**: All scripts parse correctly
- **FAILED**: Syntax errors found (must fix)

### Linting
- **PASSED**: No errors or warnings
- **PASSED (with warnings)**: Has warnings but no errors (can commit)
- **FAILED**: Has errors (must fix)
- **SKIPPED**: PSScriptAnalyzer not installed

### Tests
- **PASSED**: All tests passed
- **FAILED**: One or more tests failed (must fix)
- **NO TESTS**: Tests directory doesn't exist
- **SKIPPED**: Pester not installed

## Common Issues

### "PSScriptAnalyzer not found"
```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
```

### "Pester not found" or "Wrong Pester version"
```powershell
Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck -Scope CurrentUser
```

### "Pre-commit hook not running"
```powershell
# Reinstall hooks
.\.githooks\install-hooks.ps1

# Verify configuration
git config core.hooksPath
# Should output: .githooks
```

### "Want to bypass hook temporarily"
```powershell
# Not recommended, but sometimes necessary for WIP commits
git commit --no-verify -m "WIP: work in progress"
```

## CI/CD Pipeline

The same checks run automatically on GitHub when you:
- Push to `main`, `rewrite`, or `develop`
- Create a Pull Request to `main` or `rewrite`

View CI results:
1. Go to your PR on GitHub
2. Click the "Checks" tab
3. See detailed logs for each job

## Best Practices

1. **Run validation before committing** (or let the hook do it)
2. **Fix errors immediately** - don't let them accumulate
3. **Address warnings when practical** - they don't block commits but improve quality
4. **Add tests for new features** - keep test coverage high
5. **Check CI results** - don't merge PRs with failing checks

## More Information

For comprehensive documentation, see:
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** - Complete development workflow guide
- **[CLAUDE.md](./CLAUDE.md)** - Project architecture and guidelines
- **[AGENTS.md](./AGENTS.md)** - Detailed coding standards (if exists)

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│  PCMigrationTool - Testing Quick Reference          │
├─────────────────────────────────────────────────────┤
│  Run all checks:                                    │
│    .\Invoke-ValidationSuite.ps1                     │
│                                                     │
│  Run tests only:                                    │
│    Invoke-Pester ./tests                            │
│                                                     │
│  Run linting only:                                  │
│    Invoke-ScriptAnalyzer -Path . -Recurse `         │
│      -Settings .\.vscode\PSScriptAnalyzerSettings.  │
│         psd1                                        │
│                                                     │
│  Install hooks:                                     │
│    .\.githooks\install-hooks.ps1                    │
│                                                     │
│  Bypass hook (not recommended):                     │
│    git commit --no-verify                           │
└─────────────────────────────────────────────────────┘
```
