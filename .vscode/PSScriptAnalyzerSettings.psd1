@{
    # Severity levels: Error, Warning, Information
    Severity = @('Error', 'Warning')

    # Include default rules
    IncludeDefaultRules = $true

    # Exclude specific rules that don't apply to this project
    ExcludeRules = @(
        # We use Write-Host intentionally in catch blocks for user-facing errors
        # 'PSAvoidUsingWriteHost',  # Uncomment if you want to enforce this

        # The script intentionally uses global scope for UI components
        'PSAvoidGlobalVars',

        # Migration tool needs to handle plain text passwords for local user creation
        # This is by design for the PC migration scenario
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSAvoidUsingUsernameAndPasswordParams'
    )

    # Custom rule configurations
    Rules = @{
        PSPlaceOpenBrace = @{
            Enable = $true
            OnSameLine = $true
            NewLineAfter = $true
            IgnoreOneLineBlock = $true
        }

        PSPlaceCloseBrace = @{
            Enable = $true
            NewLineAfter = $true
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore = $false
        }

        PSUseConsistentIndentation = @{
            Enable = $true
            Kind = 'space'
            IndentationSize = 4
        }

        PSUseConsistentWhitespace = @{
            Enable = $true
            CheckOpenBrace = $true
            CheckOpenParen = $true
            CheckOperator = $true
            CheckSeparator = $true
        }

        PSAlignAssignmentStatement = @{
            Enable = $false  # Disable as it can make diffs harder to read
        }

        PSUseCorrectCasing = @{
            Enable = $true
        }

        # Security-focused rules
        # Note: Password-related rules are disabled via ExcludeRules because this is a
        # migration tool that needs to handle plain text passwords for local user creation
        PSAvoidUsingInvokeExpression = @{
            Enable = $true
        }

        # Best practices
        PSUseDeclaredVarsMoreThanAssignments = @{
            Enable = $true
        }

        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true
        }

        PSAvoidUsingCmdletAliases = @{
            Enable = $true
            # Allow common aliases that are well-known
            Whitelist = @('?', '%', 'cd', 'ls', 'cp', 'mv', 'rm')
        }

        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $false
            BlockComment = $true
            VSCodeSnippetCorrection = $true
            Placement = 'before'
        }
    }
}
