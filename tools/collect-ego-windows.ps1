# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
Collect a local, selected Windows inventory for MateBook E Go research.
.DESCRIPTION
Run with the existing PowerShell policy and permissions. This script does not
download, upload, elevate, change ExecutionPolicy, alter firmware, or start a VM.
It reports selected CIM fields, a Secure Boot query, and version/hash metadata
for the local tcblaunch.exe. A TCB hash does not establish slbounce compatibility.
Default output is JSON on stdout. -OutputPath creates one NEW file exclusively.
.EXAMPLE
powershell -NoProfile -File tools/collect-ego-windows.ps1
.EXAMPLE
powershell -NoProfile -File tools/collect-ego-windows.ps1 -OutputPath ego-windows.json
#>
[CmdletBinding()]
param([string]$OutputPath)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function New-Observation {
    param([string]$Status, [string]$Source, $Value = $null, [string]$Reason = '')
    $result = [ordered]@{ status = $Status; source = $Source }
    if ($Status -eq 'ok') { $result['value'] = $Value }
    if ($Reason) { $result['reason'] = $Reason }
    return $result
}

function Get-FailureObservation {
    param([string]$Source, $Record)
    # Do not serialize ErrorRecord: messages and target objects may include
    # usernames, machine names, local paths, or provider-specific identifiers.
    $status = 'error'
    if ($Record.Exception -is [System.UnauthorizedAccessException] -or
        $Record.Exception -is [System.Security.SecurityException] -or
        $Record.CategoryInfo.Category -eq 'PermissionDenied') {
        $status = 'permission_denied'
    } elseif ($Record.Exception -is [System.IO.FileNotFoundException] -or
              $Record.Exception -is [System.IO.DirectoryNotFoundException] -or
              $Record.CategoryInfo.Category -eq 'ObjectNotFound') {
        $status = 'missing'
    }
    return (New-Observation $status $Source)
}

function Convert-SelectedText {
    param($Value, [string]$Source)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return (New-Observation 'missing' $Source)
    }
    $text = ([string]$Value).Trim()
    $checked = $text -replace ' @ [0-9]+(?:\.[0-9]+)?\s*[GM]Hz\b', ''
    $identifier = '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|\b[0-9a-f]{24,}\b'
    if ($text.Length -gt 160 -or $text -match $identifier -or
        $checked -match '[/\\@:\r\n\x00-\x1f]' -or
        $checked -notmatch '^[\w .,+()\[\]-]+$') {
        return (New-Observation 'redacted' $Source $null 'unexpected_model_or_version_text')
    }
    foreach ($match in [regex]::Matches($text, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')) {
        $addressLike = $true
        foreach ($part in $match.Value.Split('.')) {
            if ([int]$part -gt 255) { $addressLike = $false }
        }
        if ($addressLike) {
            return (New-Observation 'redacted' $Source $null 'address_like_text')
        }
    }
    return (New-Observation 'ok' $Source $text)
}

function Convert-SelectedInteger {
    param($Value, [string]$Source)
    if ($null -eq $Value) { return (New-Observation 'missing' $Source) }
    $number = [uint64]0
    if (-not [uint64]::TryParse([string]$Value, [ref]$number)) {
        return (New-Observation 'invalid' $Source $null 'invalid_unsigned_integer')
    }
    return (New-Observation 'ok' $Source $number)
}

function Read-CimSelection {
    param([string]$ClassName, [string[]]$Properties)
    try {
        $records = @(Get-CimInstance -ClassName $ClassName -Property $Properties -ErrorAction Stop)
        if ($records.Count -eq 0) { return (New-Observation 'missing' $ClassName) }
        # These provider objects remain local. Only explicit fields below are
        # copied into the final report, never the whole CIM instance.
        return (New-Observation 'ok' $ClassName $records)
    } catch {
        return (Get-FailureObservation $ClassName $_)
    }
}

function Read-SelectedField {
    param($Selection, [string]$Name, [string]$Kind = 'text', [int]$Index = 0)
    $source = $Selection.source + ':' + $Name
    if ($Selection.status -ne 'ok') { return (New-Observation $Selection.status $source) }
    $property = $Selection.value[$Index].PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return (New-Observation 'missing' $source)
    }
    $value = $property.Value
    if ($Kind -eq 'integer') { return (Convert-SelectedInteger $value $source) }
    if ($Kind -eq 'boolean') {
        if ($value -is [bool]) { return (New-Observation 'ok' $source $value) }
        return (New-Observation 'invalid' $source $null 'not_boolean')
    }
    if ($Kind -eq 'date') {
        if ($value -is [datetime]) {
            return (New-Observation 'ok' $source $value.ToString('yyyy-MM-dd'))
        }
        return (New-Observation 'invalid' $source $null 'not_datetime')
    }
    return (Convert-SelectedText $value $source)
}

function Read-SecureBoot {
    $source = 'Confirm-SecureBootUEFI'
    try {
        $command = Get-Command -Name Confirm-SecureBootUEFI -CommandType Cmdlet -ErrorAction SilentlyContinue
        if ($null -eq $command) {
            return (New-Observation 'unknown' $source $null 'cmdlet_unavailable')
        }
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($enabled -isnot [bool]) {
            return (New-Observation 'unknown' $source $null 'unexpected_result')
        }
        return (New-Observation 'ok' $source $enabled)
    } catch {
        $failure = Get-FailureObservation $source $_
        return (New-Observation 'unknown' $source $null $failure.status)
    }
}

function Read-TcbMetadata {
    $source = 'Windows System32 tcblaunch.exe'
    $result = [ordered]@{
        file_version = (New-Observation 'not_attempted' $source)
        product_version = (New-Observation 'not_attempted' $source)
        sha256 = (New-Observation 'not_attempted' $source)
        slbounce_compatibility = (New-Observation 'not_tested' 'collector_scope')
    }
    try {
        $windowsDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
        if ([string]::IsNullOrWhiteSpace($windowsDirectory)) {
            throw [System.IO.DirectoryNotFoundException]::new()
        }
        $path = [System.IO.Path]::Combine($windowsDirectory, 'System32', 'tcblaunch.exe')
        $file = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($file.PSIsContainer) { throw [System.IO.FileNotFoundException]::new() }
    } catch {
        $failure = Get-FailureObservation $source $_
        $result.file_version = $failure
        $result.product_version = $failure
        $result.sha256 = $failure
        return $result
    }
    try {
        $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        # Numeric resource fields avoid arbitrary vendor string resources and
        # the path returned by FileVersionInfo. The binary is never executed.
        $fileVersion = '{0}.{1}.{2}.{3}' -f $version.FileMajorPart, $version.FileMinorPart, $version.FileBuildPart, $version.FilePrivatePart
        $productVersion = '{0}.{1}.{2}.{3}' -f $version.ProductMajorPart, $version.ProductMinorPart, $version.ProductBuildPart, $version.ProductPrivatePart
        $result.file_version = New-Observation 'ok' $source $fileVersion
        $result.product_version = New-Observation 'ok' $source $productVersion
    } catch {
        $result.file_version = Get-FailureObservation $source $_
        $result.product_version = $result.file_version
    }
    try {
        $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
        if ($hash.Hash -notmatch '^[0-9a-fA-F]{64}$') { throw [System.IO.InvalidDataException]::new() }
        $result.sha256 = New-Observation 'ok' $source $hash.Hash.ToLowerInvariant()
    } catch {
        $result.sha256 = Get-FailureObservation $source $_
    }
    return $result
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    [Console]::Error.WriteLine('This collector requires Windows.')
    exit 2
}

$computer = Read-CimSelection 'Win32_ComputerSystem' @('Manufacturer', 'Model', 'TotalPhysicalMemory', 'HypervisorPresent')
$processors = Read-CimSelection 'Win32_Processor' @('Name', 'Manufacturer', 'Architecture', 'NumberOfCores', 'NumberOfLogicalProcessors')
$bios = Read-CimSelection 'Win32_BIOS' @('SMBIOSBIOSVersion', 'ReleaseDate')
$operatingSystem = Read-CimSelection 'Win32_OperatingSystem' @('Version', 'BuildNumber')
$cpuRows = @()
if ($processors.status -eq 'ok') {
    for ($index = 0; $index -lt $processors.value.Count; $index++) {
        $cpuRows += [ordered]@{
            name = (Read-SelectedField $processors 'Name' 'text' $index)
            manufacturer = (Read-SelectedField $processors 'Manufacturer' 'text' $index)
            architecture_code = (Read-SelectedField $processors 'Architecture' 'integer' $index)
            cores = (Read-SelectedField $processors 'NumberOfCores' 'integer' $index)
            logical_processors = (Read-SelectedField $processors 'NumberOfLogicalProcessors' 'integer' $index)
        }
    }
    $cpuResult = New-Observation 'ok' 'Win32_Processor:selected fields' $cpuRows
} else {
    $cpuResult = New-Observation $processors.status 'Win32_Processor:selected fields'
}

$buildRevision = New-Observation 'not_attempted' 'Windows CurrentVersion:UBR'
try {
    $revision = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction Stop
    $buildRevision = Convert-SelectedInteger $revision 'Windows CurrentVersion:UBR'
} catch {
    $buildRevision = Get-FailureObservation 'Windows CurrentVersion:UBR' $_
}

$report = [ordered]@{
    schema_version = 1
    report_kind = 'ego_windows_inventory'
    collector = [ordered]@{ name = 'collect-ego-windows'; version = 1 }
    platform = [ordered]@{ os = 'Windows'; arm64_architecture_code = 12 }
    device = [ordered]@{
        manufacturer = (Read-SelectedField $computer 'Manufacturer')
        product_model = (Read-SelectedField $computer 'Model')
        bios_version = (Read-SelectedField $bios 'SMBIOSBIOSVersion')
        bios_release_date = (Read-SelectedField $bios 'ReleaseDate' 'date')
    }
    cpu = [ordered]@{ processors = $cpuResult; instruction_features = (New-Observation 'not_measured' 'collector_scope') }
    memory = [ordered]@{ total_bytes = (Read-SelectedField $computer 'TotalPhysicalMemory' 'integer') }
    operating_system = [ordered]@{
        version = (Read-SelectedField $operatingSystem 'Version')
        build = (Read-SelectedField $operatingSystem 'BuildNumber' 'integer')
        update_build_revision = $buildRevision
    }
    boot = [ordered]@{
        secure_boot = (Read-SecureBoot)
        hypervisor_present = (Read-SelectedField $computer 'HypervisorPresent' 'boolean')
        host_el2_ownership = (New-Observation 'not_tested' 'collector_scope')
    }
    tcblaunch = (Read-TcbMetadata)
    limitations = @(
        'This inventory is not the register-report schema used by check-ego-capabilities.',
        'No unique device IDs, serials, UUIDs, PnP inventories, network settings, logs or firmware blobs were collected.',
        'Review OEM-provided model/version text before sharing; no report is uploaded automatically.',
        'Processor architecture code 12 identifies ARM64; it does not establish ISA features.',
        'Secure Boot and HypervisorPresent do not establish Linux EL2 access or KVM availability.',
        'TCB version and SHA256 identify the local file; slbounce compatibility has not been tested.',
        'PAuth, NV2, 16K guest translation and macOS compatibility were not measured.'
    )
}

$json = $report | ConvertTo-Json -Depth 16
try {
    if ([string]::IsNullOrEmpty($OutputPath)) {
        [Console]::Out.WriteLine($json)
    } else {
        $stream = $null
        $writer = $null
        try {
            $stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
            $writer.WriteLine($json)
        } finally {
            if ($null -ne $writer) { $writer.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
    }
} catch {
    [Console]::Error.WriteLine('Report output failed. The destination must be a writable new file; existing files are not overwritten.')
    exit 2
}
