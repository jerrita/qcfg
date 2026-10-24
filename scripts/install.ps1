# Install the latest qcfg release. Override the target directory with $env:QCFG_INSTALL_DIR.
$ErrorActionPreference = 'Stop'

$repo = 'jerrita/qcfg'
$dir = if ($env:QCFG_INSTALL_DIR) { $env:QCFG_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\qcfg' }

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
}

$url = "https://github.com/$repo/releases/latest/download/qcfg-windows-amd64.exe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "downloading $url"
Invoke-WebRequest -Uri $url -OutFile (Join-Path $dir 'qcfg.exe') -UseBasicParsing
Write-Host "installed $dir\qcfg.exe"

$path = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($path -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$dir", 'User')
    Write-Host "added $dir to user PATH, restart the terminal to take effect"
}
