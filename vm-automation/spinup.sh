#!/usr/bin/env bash
# spinup.sh - spin up ONE pristine Windows 11 VM (Vagrant + VirtualBox) on a Linux or macOS host.
# Windows host? Use spinup.ps1 instead.
#
#   bash spinup.sh               fresh VM (any VM this folder made earlier is destroyed first)
#   HEADLESS=1 bash spinup.sh    same, but without opening the VM window
#
# Re-run it whenever you want a clean machine again.
set -euo pipefail
cd "$(dirname "$0")"   # always work next to the Vagrantfile

step() { printf '\n==> %s\n' "$*"; }

step "Checking prerequisites"
for tool in vagrant VBoxManage; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: '$tool' is not installed or not on PATH." >&2
    exit 1
  fi
done
echo "$(vagrant --version), VirtualBox $(VBoxManage --version)"

step "Destroying any previous VM so the new one is pristine"
vagrant destroy --force

step "Creating and booting Windows 11 (first run downloads the base box, several GB)"
vagrant up --provider=virtualbox

step "Verifying the guest over WinRM"
info=$(vagrant winrm --command "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List" | tr -d '\r')
echo "$info"
if [[ "$info" != *"Windows 11"* ]]; then
  echo "ERROR: the VM is up but did not report Windows 11." >&2
  exit 1
fi

step "Done: a pristine Windows 11 VM is running (VirtualBox name: win11-pristine)"
echo "Stop it: vagrant halt  |  Delete it: vagrant destroy -f  |  Fresh one: bash spinup.sh"
