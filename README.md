# CS2 Kernel Injector

A lightweight Windows kernel-mode injector based on WDM.

This project demonstrates manual mapping and CR3-based memory access techniques for interacting with usermode processes from kernel space.

## Features
- Kernel-mode injection (WDM)
- Manual mapping (no LoadLibrary)
- CR3-based cross-process memory access
- Custom communication (IOCTL / Registry callback)
- Driver concealment techniques
- PEB / LDR module parsing

## Technical Details
- IoCreateDriver initialization
- CR3 switching for virtual memory operations
- MmCopyVirtualMemory fallback
- SSDT hook (NtQuerySystemInformation)
- LDR unlink & MmUnloadedDrivers cleanup

## Usage
1. Map driver using kdmapper or equivalent loader
2. Launch usermode client
3. Attach to target process

## Build
- Visual Studio 2022
- Windows Driver Kit (WDK)
- x64 Release

## Disclaimer
This project is intended for educational and research purposes only.
Use at your own risk.