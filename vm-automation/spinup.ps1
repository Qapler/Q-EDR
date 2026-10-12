# spinup.ps1 - spin up ONE pristine Windows 11 VM (Vagrant + VirtualBox) on a Windows host.
#
#   powershell -ExecutionPolicy Bypass -File .\spinup.ps1
#       fresh VM (any VM this folder made earlier is destroyed first)
#   $env:HEADLESS = "1"; powershell -ExecutionPolicy Bypass -File .\spinup.ps1
#       same, but without opening the VM window
#
# Re-run it whenever you want a clean machine again.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot   # always work next to the Vagrantfile

function Invoke-Step {
    param([string]$Title, [scriptblock]$Action)
    Write-Host "`n==> $Title" -ForegroundColor Cyan
    & $Action
    if ($LASTEXITCODE -ne 0) { throw "Step failed: $Title (exit code $LASTEXITCODE)" }
}

# Prerequisites. The VirtualBox installer does not add VBoxManage to PATH, so look in its install folder.
if (-not (Get-Command vagrant -ErrorAction SilentlyContinue)) {
    throw "Vagrant is not installed or not on PATH."
}
$vboxDir    = if ($env:VBOX_MSI_INSTALL_PATH) { $env:VBOX_MSI_INSTALL_PATH } else { "$env:ProgramFiles\Oracle\VirtualBox" }
$vboxManage = Join-Path $vboxDir "VBoxManage.exe"
if (-not (Test-Path $vboxManage)) {
    throw "VirtualBox not found (looked for $vboxManage)."
}

Invoke-Step "Checking versions" { vagrant --version; & $vboxManage --version }
Invoke-Step "Destroying any previous VM so the new one is pristine" { vagrant destroy --force }
Invoke-Step "Creating and booting Windows 11 (first run downloads the base box, several GB)" { vagrant up --provider=virtualbox }

Write-Host "`n==> Verifying the guest over WinRM" -ForegroundColor Cyan
$info = vagrant winrm --command "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List" | Out-String
if ($LASTEXITCODE -ne 0) { throw "Could not reach the VM over WinRM (exit code $LASTEXITCODE)." }
Write-Host $info.Trim()
if ($info -notmatch "Windows 11") { throw "The VM is up but did not report Windows 11." }

Write-Host "`n==> Done: a pristine Windows 11 VM is running (VirtualBox name: win11-pristine)" -ForegroundColor Green
Write-Host "Stop it: vagrant halt  |  Delete it: vagrant destroy -f  |  Fresh one: run this script again"
