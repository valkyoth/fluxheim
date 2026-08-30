[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Config
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -LiteralPath (Join-Path $PSScriptRoot 'windows_console_signal_helper.cs')
$result = [FluxheimWindowsConsoleSignalHelper]::Run($Binary, $Config)
exit $result
