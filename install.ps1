# XoraPass CLI Windows PowerShell Installer
# Run: iwr -useb https://raw.githubusercontent.com/Ventiqo-Technologies/xorapass-cli/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo = "Ventiqo-Technologies/xorapass-cli"
$InstallDir = "$env:USERPROFILE\AppData\Local\Programs\xora"

Write-Host "[+] XoraPass CLI Windows Installer"
Write-Host "-----------------------------------"

# 1. Detect architecture
$Arch = $env:PROCESSOR_ARCHITECTURE
if ($Arch -eq "AMD64") {
    $Cpu = "amd64"
} elseif ($Arch -eq "ARM64") {
    $Cpu = "arm64"
} else {
    Write-Error "[-] Unsupported CPU Architecture: $Arch"
    exit 1
}

$BinaryName = "xora-windows-$Cpu.exe"

# 2. Fetch release metadata from GitHub
Write-Host "[*] Fetching latest release metadata from GitHub..."
$Uri = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $Release = Invoke-RestMethod -Uri $Uri -UseBasicParsing
    $DownloadUrl = ($Release.assets | Where-Object { $_.name -like "*$BinaryName*" }).browser_download_url
} catch {
    $DownloadUrl = $null
}

if (-not $DownloadUrl) {
    # Fallback to repository raw branch
    $DownloadUrl = "https://raw.githubusercontent.com/$Repo/main/dist/$BinaryName"
}

# 3. Create target directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# 4. Download Binary
$DestPath = Join-Path $InstallDir "xora.exe"
Write-Host "[*] Downloading XoraPass CLI for Windows..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestPath -UseBasicParsing

# 5. Add to User PATH env variable
Write-Host "[*] Registering Path environments..."
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    $NewPath = "$UserPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    # Update active session path variable as well
    $env:Path += ";$InstallDir"
}

Write-Host "-----------------------------------"
Write-Host "[+] XoraPass CLI successfully installed!"
Write-Host "[*] Open a NEW CMD/PowerShell terminal and run 'xora --help' to verify."

