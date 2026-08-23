[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$WslHelper,
    [string]$WslHelperSha256,
    [string]$InnoCompiler,
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-ReleaseRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )
    # Path.GetRelativePath is unavailable in Windows PowerShell 5.1's .NET
    # Framework.  All release entries must be descendants, so a validated
    # full-path prefix is both simpler and compatible with powershell.exe.
    $BaseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]'\/')
    $TargetFull = [System.IO.Path]::GetFullPath($TargetPath)
    $Prefix = $BaseFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $TargetFull.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Release path is outside its declared root: $TargetFull"
    }
    return $TargetFull.Substring($Prefix.Length).Replace('\', '/')
}

function Invoke-FrozenRuntimeCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$TimeoutSeconds = 30
    )
    $Process = Start-Process -FilePath $Executable -ArgumentList '--runtime-check' `
        -WindowStyle Hidden -PassThru
    try {
        if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
            try { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue } catch {}
            throw "The frozen $Label runtime check timed out after $TimeoutSeconds seconds."
        }
        if ($Process.ExitCode -ne 0) {
            throw "The frozen $Label failed its dependency/runtime smoke test (exit $($Process.ExitCode))."
        }
    } finally {
        $Process.Dispose()
    }
}

function Get-InnoSetupVersion {
    param(
        [Parameter(Mandatory = $true)][string]$CompilerPath
    )
    $CompilerFull = [System.IO.Path]::GetFullPath($CompilerPath)
    $RegistryRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($RegistryRoot in $RegistryRoots) {
        foreach ($Entry in @(Get-ItemProperty -Path $RegistryRoot -ErrorAction SilentlyContinue)) {
            $NameProperty = $Entry.PSObject.Properties['DisplayName']
            $VersionProperty = $Entry.PSObject.Properties['DisplayVersion']
            $LocationProperty = $Entry.PSObject.Properties['InstallLocation']
            if (-not $NameProperty -or -not $VersionProperty -or
                -not $LocationProperty -or
                $NameProperty.Value -notlike 'Inno Setup version *' -or
                $VersionProperty.Value -notmatch '^\d+\.\d+\.\d+$' -or
                -not $LocationProperty.Value) {
                continue
            }
            $RegisteredCompiler = Join-Path $LocationProperty.Value 'ISCC.exe'
            if ([System.IO.Path]::GetFullPath($RegisteredCompiler).Equals(
                    $CompilerFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $VersionProperty.Value
            }
        }
    }
    # Some managed build images omit the uninstall entry.  Older Inno Setup
    # releases carried a useful Win32 version resource, so retain that as a
    # narrow fallback while rejecting the 0.0.0.0 resource used by 6.7.3.
    $VersionInfo = (Get-Item -LiteralPath $CompilerFull).VersionInfo
    $FileVersion = '{0}.{1}.{2}' -f $VersionInfo.ProductMajorPart,
        $VersionInfo.ProductMinorPart, $VersionInfo.ProductBuildPart
    if ($FileVersion -ne '0.0.0') {
        return $FileVersion
    }
    throw "Could not prove the installed Inno Setup version for $CompilerFull"
}

$RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepositoryRoot 'dist\windows'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$BuildRoot = Join-Path $RepositoryRoot 'build\windows'
$AppDist = Join-Path $OutputDirectory 'app'
$InstallerDist = Join-Path $OutputDirectory 'installer'
$VersionPath = Join-Path $RepositoryRoot 'VERSION'
$SupervisorSource = Join-Path $RepositoryRoot 'supervisor.py'
$SupervisorClientSource = Join-Path $RepositoryRoot 'supervisor_client.py'
$WslHelperManifest = Join-Path $RepositoryRoot 'wsl_helper\Cargo.toml'
$Requirements = Join-Path $RepositoryRoot 'requirements-windows.txt'
$MainSpec = Join-Path $PSScriptRoot 'console.spec'
$SupervisorSpec = Join-Path $PSScriptRoot 'supervisor.spec'
$InstallerScript = Join-Path $PSScriptRoot 'installer.iss'
$UnsignedNotice = Join-Path $PSScriptRoot 'UNSIGNED_BUILD_NOTICE.txt'
$ChineseLanguage = Join-Path $PSScriptRoot 'languages\ChineseSimplified.isl'
$ChineseLanguageProvenance = Join-Path $PSScriptRoot 'languages\README.md'
$RequiredPythonVersion = '3.12.10'
$RequiredInnoSetupVersion = '6.7.3'
$ChineseLanguageCommit = '5680c948e1de07e71cbd27cad7d4f5e75223afba'
$RequiredChineseLanguageHash = 'bf0751fa176569c6faa2f6e17ed2734617bef325d5cc06eae030fdd0258ee778'

$NativeOsArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if (-not [Environment]::Is64BitOperatingSystem -or $NativeOsArchitecture -ne 'X64') {
    throw 'Windows x64 is required to build this release.'
}
foreach ($RequiredPath in @($VersionPath, $SupervisorSource, $SupervisorClientSource, $WslHelperManifest, $Requirements, $MainSpec, $SupervisorSpec, $InstallerScript, $UnsignedNotice, $ChineseLanguage, $ChineseLanguageProvenance)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required release source is missing: $RequiredPath"
    }
}
$ChineseLanguageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ChineseLanguage).Hash.ToLowerInvariant()
if ($ChineseLanguageHash -ne $RequiredChineseLanguageHash) {
    throw "Vendored Inno Setup Chinese translation hash mismatch: $ChineseLanguageHash"
}

$Version = (Get-Content -Raw -Encoding UTF8 -LiteralPath $VersionPath).Trim()
if ($Version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    throw "VERSION is not SemVer: $Version"
}
$InstallerVersion = ($Version -split '[+-]', 2)[0]
$SupervisorClientText = Get-Content -Raw -Encoding UTF8 -LiteralPath $SupervisorClientSource
if ($SupervisorClientText -notmatch '(?m)^SUPERVISOR_VERSION\s*=\s*["''](?<version>[0-9]+\.[0-9]+\.[0-9]+)["'']\s*$') {
    throw 'supervisor_client.py does not declare a strict SUPERVISOR_VERSION.'
}
$SupervisorVersion = $Matches.version
$SupervisorSourceText = Get-Content -Raw -Encoding UTF8 -LiteralPath $SupervisorSource
if ($SupervisorSourceText -notmatch '(?m)^SUPERVISOR_VERSION\s*=\s*["''](?<version>[0-9]+\.[0-9]+\.[0-9]+)["'']\s*$') {
    throw 'supervisor.py does not declare a strict SUPERVISOR_VERSION.'
}
if ($Matches.version -ne $SupervisorVersion) {
    throw "Supervisor implementation/client version mismatch: $($Matches.version) != $SupervisorVersion"
}
$WslHelperManifestText = Get-Content -Raw -Encoding UTF8 -LiteralPath $WslHelperManifest
if ($WslHelperManifestText -notmatch '(?m)^version\s*=\s*"(?<version>[0-9]+\.[0-9]+\.[0-9]+)"\s*$') {
    throw 'wsl_helper/Cargo.toml does not declare a strict package version.'
}
$WslHelperVersion = $Matches.version

if (-not $WslHelper) {
    $WslHelper = Join-Path $RepositoryRoot 'dist\wsl-helper-x86_64'
}
$WslHelper = [System.IO.Path]::GetFullPath($WslHelper)
if (-not (Test-Path -LiteralPath $WslHelper -PathType Leaf)) {
    throw "The statically linked WSL helper is required: $WslHelper"
}
if (-not $WslHelperSha256) {
    $WslHelperSha256 = "$WslHelper.sha256"
}
$WslHelperSha256 = [System.IO.Path]::GetFullPath($WslHelperSha256)
if (-not (Test-Path -LiteralPath $WslHelperSha256 -PathType Leaf)) {
    throw "The WSL helper SHA-256 attestation is required: $WslHelperSha256"
}
$HelperHashLine = (Get-Content -Raw -Encoding ascii -LiteralPath $WslHelperSha256).Trim()
if ($HelperHashLine -notmatch '^(?<hash>[0-9A-Fa-f]{64})(?:\s+\*?.+)?$') {
    throw 'The WSL helper SHA-256 attestation has an invalid format.'
}
$ExpectedHelperHash = $Matches.hash.ToLowerInvariant()
$ActualHelperHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WslHelper).Hash.ToLowerInvariant()
if ($ActualHelperHash -ne $ExpectedHelperHash) {
    throw "WSL helper SHA-256 mismatch: expected $ExpectedHelperHash, got $ActualHelperHash"
}

# Validate the immutable ELF identity again on Windows.  The Linux builder also
# rejects PT_INTERP and shared-library dependencies with readelf.
$HelperStream = [System.IO.File]::OpenRead($WslHelper)
try {
    $ElfHeader = New-Object byte[] 20
    if ($HelperStream.Read($ElfHeader, 0, $ElfHeader.Length) -ne $ElfHeader.Length) {
        throw 'The WSL helper is too small to be a valid ELF executable.'
    }
} finally {
    $HelperStream.Dispose()
}
if ($ElfHeader[0] -ne 0x7f -or $ElfHeader[1] -ne 0x45 -or
    $ElfHeader[2] -ne 0x4c -or $ElfHeader[3] -ne 0x46 -or
    $ElfHeader[4] -ne 2 -or $ElfHeader[5] -ne 1 -or
    $ElfHeader[18] -ne 0x3e -or $ElfHeader[19] -ne 0x00) {
    throw 'The WSL helper must be a little-endian ELF64 x86-64 executable.'
}

$PythonCandidates = @()
$PyLauncher = Get-Command py -CommandType Application -ErrorAction SilentlyContinue
if ($PyLauncher) {
    # Prefer the launcher because a valid 3.12 installation may coexist with a
    # newer default `python` on developer workstations.
    $PythonCandidates += [pscustomobject]@{
        Executable = $PyLauncher.Source
        Arguments = @('-3.12')
        Label = 'py -3.12'
    }
}
$PythonCommand = Get-Command python -CommandType Application -ErrorAction SilentlyContinue
if ($PythonCommand) {
    $PythonCandidates += [pscustomobject]@{
        Executable = $PythonCommand.Source
        Arguments = @()
        Label = 'python'
    }
}
$PerUserPython = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'
if (Test-Path -LiteralPath $PerUserPython -PathType Leaf) {
    $PythonCandidates += [pscustomobject]@{
        Executable = $PerUserPython
        Arguments = @()
        Label = 'official per-user Python 3.12'
    }
}

$PythonExe = $null
$PythonArgs = @()
$PythonRuntimeVersion = $null
$PointerBits = $null
$ObservedPythonRuntimes = @()
foreach ($Candidate in $PythonCandidates) {
    try {
        $CandidateArgs = @($Candidate.Arguments)
        $CandidateVersion = (& $Candidate.Executable @CandidateArgs -c 'import platform; print(platform.python_version())' 2>$null).Trim()
        $VersionExitCode = $LASTEXITCODE
        $CandidatePointerBits = (& $Candidate.Executable @CandidateArgs -c 'import struct; print(struct.calcsize(chr(80))*8)' 2>$null).Trim()
        $BitsExitCode = $LASTEXITCODE
        if ($VersionExitCode -ne 0 -or $BitsExitCode -ne 0) {
            continue
        }
        $ObservedPythonRuntimes += "$($Candidate.Label)=$CandidateVersion/$CandidatePointerBits-bit"
        if ($CandidateVersion -ne $RequiredPythonVersion -or $CandidatePointerBits -ne '64') {
            continue
        }
        $PythonExe = $Candidate.Executable
        $PythonArgs = $CandidateArgs
        $PythonRuntimeVersion = $CandidateVersion
        $PointerBits = $CandidatePointerBits
        break
    } catch {
        continue
    }
}
if (-not $PythonExe) {
    $Observed = if ($ObservedPythonRuntimes) {
        $ObservedPythonRuntimes -join ', '
    } else {
        'none'
    }
    throw "Python $RequiredPythonVersion x64 was not found; observed: $Observed"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory, $BuildRoot | Out-Null
$Checksums = Join-Path $OutputDirectory 'SHA256SUMS.txt'
if (Test-Path -LiteralPath $Checksums) {
    Remove-Item -LiteralPath $Checksums -Force
}
if (Test-Path -LiteralPath $AppDist) {
    Remove-Item -LiteralPath $AppDist -Recurse -Force
}
if (Test-Path -LiteralPath $InstallerDist) {
    Remove-Item -LiteralPath $InstallerDist -Recurse -Force
}

$BootstrapPythonExe = $PythonExe
$BootstrapPythonArgs = $PythonArgs
$BuildVenv = Join-Path $BuildRoot 'venv'
& $BootstrapPythonExe @BootstrapPythonArgs -m venv --clear $BuildVenv
if ($LASTEXITCODE -ne 0) { throw 'Creating the isolated Windows build environment failed.' }
$PythonExe = Join-Path $BuildVenv 'Scripts\python.exe'
$PythonArgs = @()

& $PythonExe -m pip install --disable-pip-version-check --require-hashes --requirement $Requirements
if ($LASTEXITCODE -ne 0) { throw 'Installing locked Windows build dependencies failed.' }
$ResolvedRequirements = @(& $PythonExe -m pip freeze --all |
    Where-Object { $_.Trim() } | Sort-Object)
if ($LASTEXITCODE -ne 0 -or -not $ResolvedRequirements) {
    throw 'Capturing the resolved Windows dependency inventory failed.'
}
$ResolvedDependenciesPath = Join-Path $OutputDirectory 'windows-python-dependencies.txt'
$ResolvedRequirements | Set-Content -Encoding ascii -LiteralPath $ResolvedDependenciesPath

& $PythonExe @PythonArgs -m PyInstaller --noconfirm --clean --workpath (Join-Path $BuildRoot 'supervisor') --distpath (Join-Path $BuildRoot 'supervisor-dist') $SupervisorSpec
if ($LASTEXITCODE -ne 0) { throw 'Supervisor build failed.' }
$SupervisorExe = Join-Path $BuildRoot 'supervisor-dist\console-supervisor.exe'
if (-not (Test-Path -LiteralPath $SupervisorExe -PathType Leaf)) {
    throw "Supervisor artifact is missing: $SupervisorExe"
}
Invoke-FrozenRuntimeCheck -Executable $SupervisorExe -Label 'supervisor'

& $PythonExe @PythonArgs -m PyInstaller --noconfirm --clean --workpath (Join-Path $BuildRoot 'host') --distpath $AppDist $MainSpec
if ($LASTEXITCODE -ne 0) { throw 'Tray host build failed.' }
$AppDirectory = Join-Path $AppDist '总控台'
$AppExecutable = Join-Path $AppDirectory '总控台.exe'
if (-not (Test-Path -LiteralPath $AppExecutable -PathType Leaf)) {
    throw 'The onedir tray executable was not produced.'
}
Invoke-FrozenRuntimeCheck -Executable $AppExecutable -Label 'tray host'

$InternalDirectory = Join-Path $AppDirectory '_internal'
$BundledSupervisorDir = Join-Path $InternalDirectory 'supervisors'
$BundledWslDir = Join-Path $InternalDirectory 'wsl'
New-Item -ItemType Directory -Force -Path $BundledSupervisorDir, $BundledWslDir | Out-Null
$BundledSupervisor = Join-Path $BundledSupervisorDir "console-supervisor-$SupervisorVersion.exe"
$BundledSupervisorHash = "$BundledSupervisor.sha256"
$BundledHelper = Join-Path $BundledWslDir 'wsl-helper-x86_64'
$BundledHelperHash = "$BundledHelper.sha256"
Copy-Item -LiteralPath $SupervisorExe -Destination $BundledSupervisor -Force
Copy-Item -LiteralPath $WslHelper -Destination $BundledHelper -Force
$SupervisorHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BundledSupervisor).Hash.ToLowerInvariant()
"$SupervisorHash  $([System.IO.Path]::GetFileName($BundledSupervisor))" |
    Set-Content -Encoding ascii -LiteralPath $BundledSupervisorHash
"$ExpectedHelperHash  $([System.IO.Path]::GetFileName($BundledHelper))" |
    Set-Content -Encoding ascii -LiteralPath $BundledHelperHash
$Utf8WithBom = [System.Text.UTF8Encoding]::new($true)
$UnsignedNoticeText = Get-Content -Raw -Encoding UTF8 -LiteralPath $UnsignedNotice
[System.IO.File]::WriteAllText(
    (Join-Path $AppDirectory 'UNSIGNED_BUILD_NOTICE.txt'),
    $UnsignedNoticeText,
    $Utf8WithBom
)
Copy-Item -LiteralPath $ResolvedDependenciesPath -Destination (Join-Path $AppDirectory 'windows-python-dependencies.txt') -Force

$IsccPath = $null
$InnoSetupVersion = $null
if (-not $SkipInstaller) {
    if ($InnoCompiler) {
        $IsccPath = [System.IO.Path]::GetFullPath($InnoCompiler)
        if (-not (Test-Path -LiteralPath $IsccPath -PathType Leaf)) {
            throw "Specified Inno Setup compiler was not found: $IsccPath"
        }
    } else {
        # Prefer official install locations over PATH shims.  Managed Windows
        # images can expose Chocolatey's ISCC shim ahead of a newly installed
        # per-user compiler, but the shim is not the registered compiler whose
        # pinned version can be proven below.
        $Candidates = @()
        if ($env:LOCALAPPDATA) {
            $Candidates += Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
        }
        if (${env:ProgramFiles(x86)}) {
            $Candidates += Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'
        }
        if ($env:ProgramFiles) {
            $Candidates += Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'
        }
        $Iscc = Get-Command iscc -ErrorAction SilentlyContinue
        if ($Iscc) {
            $Candidates += $Iscc.Source
        }
        $IsccPath = $Candidates |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
    }
    if (-not $IsccPath) {
        throw "Inno Setup $RequiredInnoSetupVersion (ISCC.exe) was not found."
    }
    $InnoSetupVersion = Get-InnoSetupVersion -CompilerPath $IsccPath
    if ($InnoSetupVersion -ne $RequiredInnoSetupVersion) {
        throw "Inno Setup $RequiredInnoSetupVersion is required; found $InnoSetupVersion"
    }
}

$Manifest = [ordered]@{
    schemaVersion = 1
    version = $Version
    appVersion = $Version
    supervisorVersion = $SupervisorVersion
    helperVersion = $WslHelperVersion
    innoSetupVersion = $InnoSetupVersion
    chineseTranslationCommit = $ChineseLanguageCommit
    chineseTranslationSha256 = $ChineseLanguageHash
    architecture = 'x86_64'
    unsigned = $true
    signatureStatus = 'unsigned-internal-test'
    sbom = 'local-ops-windows-x64.spdx.json'
    files = [ordered]@{}
}
$ManifestPath = Join-Path $AppDirectory 'release-manifest.json'

# SPDX 2.3 dependency inventory for the exact pinned Windows build inputs.
$SbomPackages = [System.Collections.Generic.List[object]]::new()
$SbomRelationships = [System.Collections.Generic.List[object]]::new()
$SbomPackages.Add([ordered]@{
    SPDXID = 'SPDXRef-Package-LocalOps'
    name = 'local-ops'
    versionInfo = $Version
    downloadLocation = 'https://github.com/laivincent2004-netizen/Local-Ops-Windows-Mac'
    filesAnalyzed = $false
    licenseConcluded = 'MIT'
    licenseDeclared = 'MIT'
    copyrightText = 'NOASSERTION'
    primaryPackagePurpose = 'APPLICATION'
})
$SbomPackages.Add([ordered]@{
    SPDXID = 'SPDXRef-Package-CPython'
    name = 'CPython'
    versionInfo = $PythonRuntimeVersion
    downloadLocation = 'https://www.python.org/'
    filesAnalyzed = $false
    licenseConcluded = 'NOASSERTION'
    licenseDeclared = 'NOASSERTION'
    copyrightText = 'NOASSERTION'
})
$SbomRelationships.Add([ordered]@{
    spdxElementId = 'SPDXRef-Package-LocalOps'
    relationshipType = 'CONTAINS'
    relatedSpdxElement = 'SPDXRef-Package-CPython'
})
$SbomPackages.Add([ordered]@{
    SPDXID = 'SPDXRef-Package-InnoSetupChineseSimplified'
    name = 'inno-setup-chinese-simplified-translation'
    versionInfo = $ChineseLanguageCommit
    downloadLocation = "https://github.com/jrsoftware/issrc/blob/$ChineseLanguageCommit/Files/Languages/ChineseSimplified.isl"
    filesAnalyzed = $false
    licenseConcluded = 'NOASSERTION'
    licenseDeclared = 'NOASSERTION'
    copyrightText = 'Maintainer: Zhenghan Yang (Kira); upstream notices retained in the vendored source'
})
$SbomRelationships.Add([ordered]@{
    spdxElementId = 'SPDXRef-Package-LocalOps'
    relationshipType = 'CONTAINS'
    relatedSpdxElement = 'SPDXRef-Package-InnoSetupChineseSimplified'
})
foreach ($Requirement in $ResolvedRequirements) {
    $Parts = $Requirement.Trim() -split '==', 2
    if ($Parts.Count -ne 2) { throw "Unversioned resolved Windows dependency: $Requirement" }
    $DependencyName = $Parts[0]
    $DependencyVersion = $Parts[1]
    $DependencyId = 'SPDXRef-Package-' + ($DependencyName -replace '[^A-Za-z0-9.-]', '-')
    $PurlName = [System.Uri]::EscapeDataString($DependencyName.ToLowerInvariant())
    $PurlVersion = [System.Uri]::EscapeDataString($DependencyVersion)
    $SbomPackages.Add([ordered]@{
        SPDXID = $DependencyId
        name = $DependencyName
        versionInfo = $DependencyVersion
        downloadLocation = 'NOASSERTION'
        filesAnalyzed = $false
        licenseConcluded = 'NOASSERTION'
        licenseDeclared = 'NOASSERTION'
        copyrightText = 'NOASSERTION'
        primaryPackagePurpose = 'LIBRARY'
        externalRefs = @([ordered]@{
            referenceCategory = 'PACKAGE-MANAGER'
            referenceType = 'purl'
            referenceLocator = "pkg:pypi/$PurlName@$PurlVersion"
        })
    })
    $SbomRelationships.Add([ordered]@{
        spdxElementId = 'SPDXRef-Package-LocalOps'
        relationshipType = 'DEPENDS_ON'
        relatedSpdxElement = $DependencyId
    })
}
foreach ($BundledPackage in @(
    @{ Id = 'SPDXRef-Package-Supervisor'; Name = 'local-ops-supervisor'; Version = $SupervisorVersion },
    @{ Id = 'SPDXRef-Package-WSLHelper'; Name = 'local-ops-wsl-helper'; Version = $WslHelperVersion }
)) {
    $SbomPackages.Add([ordered]@{
        SPDXID = $BundledPackage.Id
        name = $BundledPackage.Name
        versionInfo = $BundledPackage.Version
        downloadLocation = 'NOASSERTION'
        filesAnalyzed = $false
        licenseConcluded = 'MIT'
        licenseDeclared = 'MIT'
        copyrightText = 'NOASSERTION'
    })
    $SbomRelationships.Add([ordered]@{
        spdxElementId = 'SPDXRef-Package-LocalOps'
        relationshipType = 'CONTAINS'
        relatedSpdxElement = $BundledPackage.Id
    })
}
$Sbom = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "local-ops-$Version-windows-x64"
    documentNamespace = "https://github.com/laivincent2004-netizen/Local-Ops-Windows-Mac/releases/download/v$Version/local-ops-windows-x64.spdx.json"
    creationInfo = [ordered]@{
        created = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        creators = @('Tool: packaging/windows/build.ps1')
    }
    documentDescribes = @('SPDXRef-Package-LocalOps')
    packages = $SbomPackages
    relationships = $SbomRelationships
}
$SbomPath = Join-Path $OutputDirectory 'local-ops-windows-x64.spdx.json'
$Sbom | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $SbomPath
Copy-Item -LiteralPath $SbomPath -Destination (Join-Path $AppDirectory 'local-ops-windows-x64.spdx.json') -Force

# Finalize the application manifest after the bundled SBOM exists.  The
# manifest intentionally excludes itself and hashes every other installed file.
$Manifest.files = [ordered]@{}
foreach ($File in Get-ChildItem -LiteralPath $AppDirectory -File -Recurse | Sort-Object FullName) {
    if ($File.FullName -eq $ManifestPath) { continue }
    $Relative = Get-ReleaseRelativePath -BasePath $AppDirectory -TargetPath $File.FullName
    $Manifest.files[$Relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath $File.FullName).Hash.ToLowerInvariant()
}
$Manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -LiteralPath $ManifestPath
$ManifestFilePaths = @($Manifest.files.Keys)
$InstalledFilePaths = @(
    Get-ChildItem -LiteralPath $AppDirectory -File -Recurse |
        Where-Object { $_.FullName -ne $ManifestPath } |
        ForEach-Object {
            Get-ReleaseRelativePath -BasePath $AppDirectory -TargetPath $_.FullName
        }
)
if ($InstalledFilePaths.Count -ne $ManifestFilePaths.Count) {
    throw 'Release manifest does not cover every installed application file.'
}
foreach ($InstalledFilePath in $InstalledFilePaths) {
    if ($ManifestFilePaths -notcontains $InstalledFilePath) {
        throw "Installed application file is absent from release manifest: $InstalledFilePath"
    }
}
$NoticeArtifact = Join-Path $OutputDirectory 'UNSIGNED_BUILD_NOTICE.txt'
Copy-Item -LiteralPath $UnsignedNotice -Destination $NoticeArtifact -Force

if (-not $SkipInstaller) {
    New-Item -ItemType Directory -Force -Path $InstallerDist | Out-Null
    # Inno Setup before 6.3 requires a BOM to identify UTF-8 .iss and
    # InfoBeforeFile input.  Compile a generated BOM copy so Chinese product
    # names remain correct on any supported Inno Setup 6 installation.
    $CompilerInstallerScript = Join-Path $BuildRoot 'installer-utf8.iss'
    [System.IO.File]::WriteAllText(
        $CompilerInstallerScript,
        (Get-Content -Raw -Encoding UTF8 -LiteralPath $InstallerScript),
        $Utf8WithBom
    )
    & $IsccPath "/DAppVersion=$InstallerVersion" "/DSourceDir=$AppDirectory" "/DOutputDir=$InstallerDist" "/DLanguageDir=$($ChineseLanguage | Split-Path -Parent)" $CompilerInstallerScript
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup build failed.' }
}

$ArtifactPaths = @($ManifestPath, $SbomPath, $NoticeArtifact, $ResolvedDependenciesPath)
if (-not $SkipInstaller) {
    $ArtifactPaths += Get-ChildItem -LiteralPath $InstallerDist -Filter '*-setup.exe' -File |
        Select-Object -ExpandProperty FullName
}
$ArtifactPaths = $ArtifactPaths | Sort-Object
foreach ($ArtifactPath in $ArtifactPaths) {
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToLowerInvariant()
    $RelativeArtifactPath = Get-ReleaseRelativePath -BasePath $OutputDirectory -TargetPath $ArtifactPath
    "$Hash  $RelativeArtifactPath" | Add-Content -Encoding utf8 -LiteralPath $Checksums
}

# Authenticode insertion contract for stable releases: sign and verify the
# PyInstaller host/supervisor outputs *before* copying them and generating the
# companion hashes + release manifest; then compile, sign and verify the
# installer *before* this top-level SHA256SUMS pass.  Never mutate a binary
# after its containing manifest/checksum is finalized. Internal v1 stays unsigned.
Write-Output "Windows release $Version built under $OutputDirectory"
