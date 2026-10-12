\# Windows 11 VM automation



Spins up one fresh Windows 11 VM using Vagrant + VirtualBox.



\## Requirements

\- VirtualBox 7.2, Vagrant 2.4.9+

\- Virtualization enabled in BIOS, Hyper-V off

\- \~50 GB free disk, 8+ GB RAM



\## Run

Windows: powershell -ExecutionPolicy Bypass -File .\\spinup.ps1

Linux/macOS: bash spinup.sh



Each run destroys the previous VM and creates a new one.

The first run downloads the base box (several GB); later runs reuse it.



Note: the base box is a Windows 11 Enterprise Evaluation image (the license watermark is expected).

