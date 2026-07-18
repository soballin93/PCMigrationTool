[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version = '1.0.4'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $root 'PCMigrationTool.sln'
$project = Join-Path $root 'src\PCMigrationTool\PCMigrationTool.csproj'
$artifacts = Join-Path $root 'artifacts'
$publish = Join-Path $artifacts 'publish'
$packageName = "PCMigrationTool-$Version-win-x64"
$staging = Join-Path $artifacts $packageName
$zip = Join-Path $artifacts "$packageName.zip"

Remove-Item $publish, $staging, $zip, "$zip.sha256" -Recurse -Force -ErrorAction SilentlyContinue

dotnet restore $solution
dotnet build $solution --configuration Release --no-restore "/p:Version=$Version"
dotnet test $solution --configuration Release --no-build
dotnet publish $project --configuration Release --no-build --output $publish "/p:Version=$Version"

New-Item -ItemType Directory -Path $staging | Out-Null
Copy-Item (Join-Path $publish 'PCMigrationTool.exe') $staging
Copy-Item (Join-Path $root 'README.md') $staging
Copy-Item (Join-Path $root 'CHANGELOG.md') $staging
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip -CompressionLevel Optimal

$hash = Get-FileHash -Algorithm SHA256 $zip
"$($hash.Hash.ToLowerInvariant())  $($hash.Path | Split-Path -Leaf)" |
    Set-Content -LiteralPath "$zip.sha256" -Encoding ascii

Write-Host "Release executable: $(Join-Path $publish 'PCMigrationTool.exe')"
Write-Host "Release package:    $zip"
Write-Host "SHA-256:            $($hash.Hash)"
