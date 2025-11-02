# Development Workflow Guide

This guide explains the development pipeline for PCMigrationTool, designed to maintain code stability while enabling rapid iteration.

## Table of Contents

- [Quick Start](#quick-start)
- [Development Pipeline](#development-pipeline)
- [Testing Strategy](#testing-strategy)
- [Continuous Integration](#continuous-integration)
- [Code Quality Standards](#code-quality-standards)
- [Branching Strategy](#branching-strategy)
- [Release Process](#release-process)

## Quick Start

### Initial Setup

1. **Install Required Modules**
   ```powershell
   # Install PSScriptAnalyzer for linting
   Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

   # Install Pester for testing
   Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -SkipPublisherCheck
   ```

2. **Install Git Hooks**
   ```powershell
   # Run from repository root
   .\.githooks\install-hooks.ps1
   ```

   This configures automatic validation before each commit.

### Daily Development Workflow

1. **Create a feature branch**
   ```powershell
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** to `PCSwapTool.ps1` or other files

3. **Run local tests** (optional but recommended)
   ```powershell
   # Run all tests
   Invoke-Pester ./tests

   # Run specific test file
   Invoke-Pester ./tests/PCSwapTool.Tests.ps1

   # Run with verbose output
   Invoke-Pester ./tests -Output Detailed
   ```

4. **Run linter** (optional but recommended)
   ```powershell
   # Analyze all PowerShell files
   Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\.vscode\PSScriptAnalyzerSettings.psd1

   # Analyze specific file
   Invoke-ScriptAnalyzer -Path .\PCSwapTool.ps1 -Settings .\.vscode\PSScriptAnalyzerSettings.psd1
   ```

5. **Commit your changes**
   ```powershell
   git add .
   git commit -m "Your descriptive commit message"
   ```

   The pre-commit hook will automatically:
   - Validate PowerShell syntax
   - Run PSScriptAnalyzer
   - Block commits if errors are found
   - Show warnings (but allow commits)

6. **Push and create PR**
   ```powershell
   git push origin feature/your-feature-name
   ```

   Create a Pull Request on GitHub, which triggers:
   - Full CI pipeline
   - All automated tests
   - Security scanning

## Development Pipeline

### Pipeline Overview

```
Local Development
    ↓
Pre-commit Hooks (Syntax + Linting)
    ↓
Push to GitHub
    ↓
CI Pipeline (GitHub Actions)
    ├─ Syntax Validation
    ├─ PSScriptAnalyzer (Linting)
    ├─ Pester Tests
    └─ Security Scan
    ↓
Code Review
    ↓
Merge to Main
    ↓
Release
```

### What Gets Validated

1. **Syntax Validation**: Ensures PowerShell parses without errors
2. **Code Linting**: PSScriptAnalyzer checks for best practices and common issues
3. **Unit Tests**: Pester tests validate functionality and structure
4. **Security Scan**: Checks for security vulnerabilities and bad practices

## Testing Strategy

### Test Organization

- **Location**: All tests live in the `./tests` directory
- **Naming**: Test files must end with `.Tests.ps1` (e.g., `PCSwapTool.Tests.ps1`)
- **Framework**: Pester 5.x is used for all testing

### Test Categories

1. **Script Validation Tests**
   - Syntax checking
   - Structure validation
   - Required function presence

2. **Function Logic Tests**
   - Helper function behavior
   - Path handling
   - Error handling

3. **Security Tests**
   - No hardcoded credentials
   - Safe use of Invoke-Expression
   - Input validation

4. **Code Quality Tests**
   - Function length limits
   - Proper error handling
   - Logging usage

### Writing New Tests

When adding new functionality, add corresponding tests:

```powershell
Describe "Your New Feature" {
    Context "Specific Behavior" {
        It "Should do something specific" {
            # Arrange
            $testValue = "something"

            # Act
            $result = YourFunction -Parameter $testValue

            # Assert
            $result | Should -Be "expected"
        }
    }
}
```

### Running Tests

```powershell
# Run all tests with detailed output
Invoke-Pester ./tests -Output Detailed

# Run tests and generate coverage report (future enhancement)
$config = New-PesterConfiguration
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = './PCSwapTool.ps1'
Invoke-Pester -Configuration $config

# Run specific test by name
Invoke-Pester ./tests -FullNameFilter "*Should have no syntax errors*"
```

## Continuous Integration

### GitHub Actions Workflows

The CI pipeline (`.github/workflows/ci.yml`) runs automatically on:
- Pushes to `main`, `rewrite`, or `develop` branches
- Pull requests targeting `main` or `rewrite`

### CI Jobs

1. **lint-and-test**
   - Installs PSScriptAnalyzer and Pester
   - Runs linting with configured rules
   - Validates syntax for all PowerShell files
   - Executes all Pester tests
   - Uploads test results as artifacts

2. **security-scan**
   - Runs security-focused PSScriptAnalyzer rules
   - Checks for common security issues
   - Provides warnings (doesn't block builds)

### Viewing CI Results

1. Go to your PR on GitHub
2. Check the "Checks" tab
3. Click on individual jobs to see detailed logs
4. Download test result artifacts if needed

### Troubleshooting CI Failures

If CI fails:

1. **Check the error logs** in the GitHub Actions tab
2. **Reproduce locally**:
   ```powershell
   # Run the same checks locally
   Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\.vscode\PSScriptAnalyzerSettings.psd1
   Invoke-Pester ./tests
   ```
3. **Fix the issues** and push again
4. CI will automatically re-run

## Code Quality Standards

### PSScriptAnalyzer Rules

Configuration: `.vscode/PSScriptAnalyzerSettings.psd1`

**Key Rules Enforced:**
- **Security**: No plain-text passwords, safe Invoke-Expression usage
- **Consistency**: Consistent indentation, brace placement, whitespace
- **Best Practices**: Declared variables used, proper error handling
- **Style**: Correct casing, no unnecessary aliases

**Exceptions:**
- `PSAvoidGlobalVars`: Disabled (GUI requires global scope)
- `PSAvoidUsingWriteHost`: Allowed in catch blocks for user feedback

### Coding Standards

Follow these standards (detailed in `CLAUDE.md` and `AGENTS.md`):

1. **Always use `Set-StrictMode -Version Latest`**
2. **Defensive property access**: Use `$obj.PSObject.Properties['PropName']`
3. **Path operations**: Always use `Join-Path`, `Split-Path`, `Test-Path`
4. **Error handling**: Wrap risky operations in try-catch blocks
5. **Logging**: Use `Write-Log` for user-facing operations
6. **Comments**: Provide comment-based help for all functions

### Version Updates

When changing behavior, update **all three**:

1. **Script header comment** (top of file)
2. **`$ProgramVersion` variable**
3. **`.CHANGELOG` section** in comment-based help

Format:
```powershell
# Version: 0.5.34
# Date: 2025-11-02

$ProgramVersion = '0.5.34'

# .CHANGELOG
# 0.5.34 - 2025-11-02
#   - Added feature X
#   - Fixed bug Y
```

## Branching Strategy

### Branch Types

- **`main`**: Production-ready code, released versions only
- **`rewrite`**: Current development branch (primary work happens here)
- **`develop`**: Optional staging branch for integration testing
- **`feature/*`**: Feature branches for new functionality
- **`fix/*`**: Bug fix branches
- **`hotfix/*`**: Emergency fixes for production

### Workflow

1. **Feature Development**:
   ```powershell
   git checkout rewrite
   git pull origin rewrite
   git checkout -b feature/my-feature
   # ... make changes ...
   git push origin feature/my-feature
   # Create PR to rewrite
   ```

2. **Bug Fixes**:
   ```powershell
   git checkout rewrite
   git checkout -b fix/bug-description
   # ... fix bug ...
   git push origin fix/bug-description
   # Create PR to rewrite
   ```

3. **Hotfixes** (for production issues):
   ```powershell
   git checkout main
   git checkout -b hotfix/critical-fix
   # ... fix issue ...
   git push origin hotfix/critical-fix
   # Create PR to main (and backport to rewrite)
   ```

### Pull Request Guidelines

**Before Creating a PR:**
- [ ] All tests pass locally
- [ ] PSScriptAnalyzer shows no errors
- [ ] Version number updated (if applicable)
- [ ] Changelog updated
- [ ] Code follows style guidelines

**PR Description Should Include:**
- Summary of changes
- Motivation/context
- Testing performed
- Screenshots (if GUI changes)
- Breaking changes (if any)

## Release Process

### Pre-Release Checklist

1. **Verify all tests pass**
   ```powershell
   Invoke-Pester ./tests -Output Detailed
   ```

2. **Run full linting**
   ```powershell
   Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\.vscode\PSScriptAnalyzerSettings.psd1
   ```

3. **Update version number** in all three locations

4. **Update CHANGELOG** with release notes

5. **Manual testing** on Windows 10 and Windows 11
   - Test gather phase
   - Test restore phase
   - Test resume operations (system and user context)
   - Test Chrome password export
   - Test default apps guidance

6. **Create release branch**
   ```powershell
   git checkout -b release/v0.5.34
   ```

7. **Merge to main**
   ```powershell
   git checkout main
   git merge release/v0.5.34
   git tag -a v0.5.34 -m "Release version 0.5.34"
   git push origin main --tags
   ```

8. **Create GitHub Release**
   - Go to GitHub Releases
   - Create new release from tag
   - Attach script file
   - Add release notes

### Hotfix Process

For critical production issues:

1. Create hotfix branch from `main`
2. Fix the issue
3. Update version (patch increment: 0.5.34 → 0.5.35)
4. Merge to `main` with new tag
5. **Important**: Backport to `rewrite` branch

## Best Practices

### For Maximum Stability

1. **Always run tests before pushing**
2. **Never bypass pre-commit hooks** (unless absolutely necessary)
3. **Keep changes small and focused**
4. **Write tests for new features**
5. **Review PSScriptAnalyzer warnings** even if they don't block commits
6. **Test on actual Windows 10/11 machines** before releasing
7. **Keep resume logic synchronized** across manifest, state, and resume functions

### For Faster Development

1. **Use feature branches** for parallel development
2. **Run tests in watch mode** during development (future enhancement)
3. **Leverage CI artifacts** to debug test failures
4. **Use `git commit --no-verify`** sparingly for work-in-progress commits
5. **Create draft PRs** for early feedback

### Common Pitfalls to Avoid

1. ❌ **Don't skip StrictMode compatibility checks**
2. ❌ **Don't use string concatenation for paths**
3. ❌ **Don't access properties without defensive checks**
4. ❌ **Don't commit without updating version/changelog**
5. ❌ **Don't bypass CI failures without investigation**
6. ❌ **Don't merge PRs without review**

## Troubleshooting

### "Pre-commit hook failed"

```powershell
# See what failed
git commit -m "message"

# Fix issues, then commit again
git add .
git commit -m "message"

# Or bypass (not recommended)
git commit --no-verify -m "message"
```

### "PSScriptAnalyzer not found"

```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
```

### "Pester tests won't run"

```powershell
# Ensure Pester 5.x is installed
Get-Module -ListAvailable Pester

# Install/update if needed
Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

### "Git hooks not running"

```powershell
# Verify hooks configuration
git config core.hooksPath

# Should output: .githooks

# If not set, run install script again
.\.githooks\install-hooks.ps1
```

### "CI passes but script fails locally"

This indicates an environment difference:
- Check PowerShell version (should be 5.1)
- Verify Windows version
- Check for missing dependencies (BouncyCastle, SQLite DLLs)
- Review file paths and permissions

## Resources

- **Pester Documentation**: https://pester.dev/
- **PSScriptAnalyzer**: https://github.com/PowerShell/PSScriptAnalyzer
- **GitHub Actions**: https://docs.github.com/en/actions
- **PowerShell Best Practices**: https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-development-guidelines

## Getting Help

If you encounter issues with the development pipeline:

1. Check this guide first
2. Review `CLAUDE.md` and `AGENTS.md` for project-specific guidance
3. Check CI logs on GitHub Actions
4. Run validation locally to reproduce issues
5. Create an issue on GitHub with details

---

**Remember**: The goal is to ship production-ready code quickly. The automated pipeline catches issues early so you can iterate with confidence.
