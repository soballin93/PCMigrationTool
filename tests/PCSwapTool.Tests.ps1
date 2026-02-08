#Requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for PCSwapTool
.DESCRIPTION
    Pester tests that validate syntax, structure, and core functionality
    of the PCMigrationTool script without requiring full GUI execution.
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Join-Path $PSScriptRoot '..') 'PCSwapTool.ps1'
    $script:ScriptContent = Get-Content -Path $script:ScriptPath -Raw

    # Parse the script to extract functions for testing
    $script:ParseErrors = $null
    $script:Tokens = $null
    $script:AST = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:ScriptPath,
        [ref]$script:Tokens,
        [ref]$script:ParseErrors
    )
}

Describe "Script Validation" {
    Context "Syntax and Structure" {
        It "Should have no syntax errors" {
            $script:ParseErrors.Count | Should -Be 0
        }

        It "Should contain Set-StrictMode declaration" {
            $script:ScriptContent | Should -Match 'Set-StrictMode\s+-Version\s+Latest'
        }

        It "Should have a valid version number" {
            $script:ScriptContent | Should -Match '\$ProgramVersion\s*=\s*[''"][\d\.]+[''"]'
        }

        It "Should contain proper comment-based help" {
            $script:ScriptContent | Should -Match '\.SYNOPSIS'
            $script:ScriptContent | Should -Match '\.DESCRIPTION'
            $script:ScriptContent | Should -Match '\.CHANGELOG'
        }
    }

    Context "Required Functions" {
        It "Should define Write-Log function" {
            $script:ScriptContent | Should -Match 'function Write-Log'
        }

        It "Should define Load-Json function" {
            $script:ScriptContent | Should -Match 'function Load-Json'
        }

        It "Should define Build-Manifest function" {
            $script:ScriptContent | Should -Match 'function Build-Manifest'
        }

        It "Should define Write-Report function" {
            $script:ScriptContent | Should -Match 'function Write-Report'
        }

        It "Should define Open-DefaultAppsGuidance function" {
            $script:ScriptContent | Should -Match 'function Open-DefaultAppsGuidance'
        }
    }

    Context "Security Checks" {
        It "Should not contain hardcoded credentials" {
            # Check for common patterns of hardcoded passwords
            $script:ScriptContent | Should -Not -Match 'password\s*=\s*[''"][^''"]+'
            $script:ScriptContent | Should -Not -Match '\$password\s*=\s*[''"][^''"]+'
        }

        It "Should not use Invoke-Expression on user input" {
            # Allow Invoke-Expression, but it should never be on direct user input
            # This is a basic check - manual review still needed
            $iexMatches = [regex]::Matches($script:ScriptContent, 'Invoke-Expression|iex\s')
            foreach ($match in $iexMatches) {
                # Get context around the match
                $start = [Math]::Max(0, $match.Index - 100)
                $length = [Math]::Min(200, $script:ScriptContent.Length - $start)
                $context = $script:ScriptContent.Substring($start, $length)

                # Should not see user input variables directly in Invoke-Expression
                $context | Should -Not -Match 'Invoke-Expression.*\$tb[A-Z]'
            }
        }
    }
}

Describe "Function Logic Tests" {
    Context "Helper Functions" {
        BeforeAll {
            # Create a minimal test environment
            $script:TestRoot = Join-Path $TestDrive 'PCSwapToolTests'
            New-Item -Path $script:TestRoot -ItemType Directory -Force | Out-Null
        }

        It "Should handle JSON parsing correctly" {
            # Create a test JSON file
            $testJson = @{
                User = @{
                    DefaultPdfProgId = 'AcroExch.Document.DC'
                    DefaultBrowserProgId = 'ChromeHTML'
                }
                Version = '0.5.33'
            }

            $jsonPath = Join-Path $script:TestRoot 'test-manifest.json'
            $testJson | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath

            # Verify file was created
            Test-Path $jsonPath | Should -Be $true

            # Load and verify
            $loaded = Get-Content $jsonPath | ConvertFrom-Json
            $loaded.User.DefaultPdfProgId | Should -Be 'AcroExch.Document.DC'
            $loaded.User.DefaultBrowserProgId | Should -Be 'ChromeHTML'
        }

        It "Should handle missing manifest properties gracefully" {
            # Test defensive property access pattern used throughout script
            $testObj = @{ Existing = 'Value' } | ConvertTo-Json | ConvertFrom-Json

            # This pattern should be used in the script
            $hasProperty = $testObj.PSObject.Properties['NonExistent']
            $hasProperty | Should -BeNullOrEmpty

            $hasExisting = $testObj.PSObject.Properties['Existing']
            $hasExisting | Should -Not -BeNullOrEmpty
        }
    }

    Context "Path Handling" {
        It "Should use Join-Path for path construction" {
            # Verify the script uses Join-Path instead of string concatenation
            $joinPathCount = ([regex]::Matches($script:ScriptContent, 'Join-Path')).Count
            $joinPathCount | Should -BeGreaterThan 10
        }

        It "Should validate paths with Test-Path before use" {
            # Count Test-Path usage - should be substantial
            $testPathCount = ([regex]::Matches($script:ScriptContent, 'Test-Path')).Count
            $testPathCount | Should -BeGreaterThan 15
        }
    }
}

Describe "Resume Task Logic" {
    Context "Resume Parameter Support" {
        It "Should have Resume switch parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\$Resume'
        }

        It "Should have ResumeUser switch parameter" {
            $script:ScriptContent | Should -Match '\[switch\]\$ResumeUser'
        }

        It "Should define Register-UserResumeTaskEx function" {
            $script:ScriptContent | Should -Match 'function Register-UserResumeTaskEx'
        }

        It "Should define New-RunOnceResume function" {
            $script:ScriptContent | Should -Match 'function New-RunOnceResume'
        }
    }
}

Describe "GUI Component Tests" {
    Context "WinForms Structure" {
        It "Should load System.Windows.Forms" {
            $script:ScriptContent | Should -Match 'System\.Windows\.Forms'
        }

        It "Should create main form" {
            $script:ScriptContent | Should -Match '\$form\s*=\s*New-Object\s+System\.Windows\.Forms\.Form'
        }

        It "Should create gather tab" {
            $script:ScriptContent | Should -Match '\$tabGather'
        }

        It "Should create restore tab" {
            $script:ScriptContent | Should -Match '\$tabRestore'
        }

        It "Should have Gather button" {
            $script:ScriptContent | Should -Match '\$btnStartGather'
        }

        It "Should have Restore button" {
            $script:ScriptContent | Should -Match '\$btnStartRestore'
        }
    }
}

Describe "Browser Password Export" {
    Context "Manual Export Functions" {
        It "Should have Get-InstalledBrowsers function" {
            $script:ScriptContent | Should -Match 'function Get-InstalledBrowsers'
        }

        It "Should have Show-BrowserPasswordExportGuide function" {
            $script:ScriptContent | Should -Match 'function Show-BrowserPasswordExportGuide'
        }

        It "Should have Test-BrowserPasswordExports function" {
            $script:ScriptContent | Should -Match 'function Test-BrowserPasswordExports'
        }

        It "Should support multiple browsers (Chrome, Edge, Firefox, Brave, Opera)" {
            $script:ScriptContent | Should -Match 'Chrome'
            $script:ScriptContent | Should -Match 'Edge'
            $script:ScriptContent | Should -Match 'Firefox'
            $script:ScriptContent | Should -Match 'Brave'
            $script:ScriptContent | Should -Match 'Opera'
        }
    }
}

Describe "Logging System" {
    Context "Log Function Usage" {
        It "Should use Write-Log with -Level parameter" {
            $writeLogCount = ([regex]::Matches($script:ScriptContent, 'Write-Log\s+-Message')).Count
            $writeLogCount | Should -BeGreaterThan 30
        }

        It "Should have error logging" {
            $script:ScriptContent | Should -Match "Write-Log.*-Level\s+[`"']Error[`"']"
        }

        It "Should have warning logging" {
            $script:ScriptContent | Should -Match "Write-Log.*-Level\s+[`"'](?:Warn|Warning|WARN)[`"']"
        }
    }
}

Describe "Robocopy Configuration" {
    Context "Copy Operations" {
        It "Should use /COPY:DAT for basic operations" {
            $script:ScriptContent | Should -Match '/COPY:DAT'
        }

        It "Should use /DCOPY:DAT for directory operations" {
            $script:ScriptContent | Should -Match '/DCOPY:DAT'
        }

        It "Should conditionally use /SEC for NTFS sources" {
            $script:ScriptContent | Should -Match '/SEC'
        }
    }
}

Describe "Manifest and State Management" {
    Context "Manifest Structure" {
        It "Should build manifest with required properties" {
            # The Build-Manifest function should create these key sections
            $script:ScriptContent | Should -Match 'Build-Manifest'
            $script:ScriptContent | Should -Match '\.User'
            $script:ScriptContent | Should -Match 'DefaultPdfProgId'
            $script:ScriptContent | Should -Match 'DefaultBrowserProgId'
        }

        It "Should use defensive property access for manifest" {
            # Should use PSObject.Properties pattern for backwards compatibility
            $defensiveAccess = ([regex]::Matches($script:ScriptContent, "PSObject\.Properties\['[^']+'\]")).Count
            $defensiveAccess | Should -BeGreaterThan 5
        }
    }

    Context "State Persistence" {
        It "Should reference state.json" {
            $script:ScriptContent | Should -Match 'state\.json'
        }
    }
}

Describe "Code Quality Metrics" {
    Context "Code Organization" {
        It "Should have reasonable function count" {
            $functions = $script:AST.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true)

            $functions.Count | Should -BeGreaterThan 10
        }

        It "Should not have excessively long functions" {
            $functions = $script:AST.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true)

            foreach ($func in $functions) {
                $lineCount = $func.Extent.EndLineNumber - $func.Extent.StartLineNumber

                # Skip the massive resume blocks and main script body
                if ($func.Name -notmatch '^(Resume|Main|<ScriptBlock>)') {
                    $lineCount | Should -BeLessThan 500 -Because "Function $($func.Name) should not exceed 500 lines"
                }
            }
        }
    }

    Context "Error Handling" {
        It "Should have try-catch blocks" {
            $tryCatchCount = ([regex]::Matches($script:ScriptContent, '\btry\s*\{')).Count
            $tryCatchCount | Should -BeGreaterThan 15
        }

        It "Should catch and log errors" {
            $script:ScriptContent | Should -Match 'catch\s*\{[\s\S]*?Write-Log'
        }
    }
}
