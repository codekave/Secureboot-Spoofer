# SecurebootSpoof

Runtime SecureBoot spoofer for Windows 10/11. Patches every query surface from a manually-mapped kernel driver no registered callbacks, no SSDT hooks, no visible driver object.

> Full technical write-up at **[hollowsec.xyz](https://hollowsec.xyz)**

## Overview

Windows exposes SecureBoot state through multiple independent query paths. A spoofer that only patches one will fail the others this driver patches all of them simultaneously on load.

| Surface | Method |
|---|---|
| `HKLM\...\SecureBoot\State\UEFISecureBootEnabled` | `ZwSetValueKey` no callback |
| `HKLM\...\SecureBoot\State\SecureBootCapable` | `ZwSetValueKey` |
| `HKLM\...\SecureBoot\Servicing\DeviceAttributes` | `ZwSetValueKey` |
| `NtQuerySystemInformation` class 145 | RIP-relative sig → direct kernel global patch |
| `SharedUserData->DbgSecureBootEnabled` | Direct write via `0xFFFFF78000000000` |
| EFI `SecureBoot` | Inline hook on unexported `NtQuerySystemEnvironmentValueEx` |
| EFI `SetupMode` | Same hook returns `0x00` |
| EFI `AuditMode` | Same hook returns `0x00` |
| EFI `DeployedMode` | Same hook returns `0x01` |
| EFI `SecureBootEnable` | Same hook, separate GUID `{f0a30bc7...}` |


## How It Works

### Registry
Direct `ZwSetValueKey` write on load. No `CmRegisterCallbackEx` callback leaves nothing enumerable.

### Class 145 Kernel Global
`NtQuerySystemInformation(145)` dispatches through a triple-nested jump table in `ExpQuerySystemInformation` → `SeSecureBootQueryInformation`, which reads a single dword global. A signature scan resolves the RIP-relative displacement to the global and ORs `0x09` (bit 0 = SecureBootEnabled, bit 3 = SecureBootCapable).

```
8A 05 ?? ?? ?? ??       mov al, [rip+d]     ; SecureBootEnabled
24 01 88 02             and al,1 / mov [rdx],al
8B 05 ?? ?? ?? ??       mov eax, [rip+d]    ; SecureBootCapable
C1 E8 03 24 01 88 42 01 shr/and/mov [rdx+1]
```

### SharedUserData
`KUSER_SHARED_DATA` is mapped at `0xFFFFF78000000000` (kernel-writable). `DbgSecureBootEnabled` is bit 7 of `SharedDataFlags` at offset `0x2EC`. Single assignment, no MDL needed. PatchGuard-safe data write only.

### EFI Variable Hook
`NtQuerySystemEnvironmentValueEx` is not exported by ntoskrnl. Located via a 46-byte prologue signature:

```
40 53 56 57 41 54 41 55 41 56 41 57  push rbx/rsi/rdi/r12/r13/r14/r15
48 81 EC 80 00 00 00                 sub rsp, 0x80
48 8B 05 ?? ?? ?? ??                 mov rax, [rip+d]   (security cookie)
48 33 C4                             xor rax, rsp
48 89 44 24 78                       mov [rsp+0x78], rax
4D 8B E1  4D 8B F8  4C 8B F2  48 8B F9
```

Hooked via MDL-backed writable mapping. A 12-byte trampoline (`48 B8 <addr> FF E0`) is written through the MDL alias. The hook intercepts all five SecureBoot-related EFI variables by GUID + name and returns spoofed values. All other EFI variable reads pass through to the original function unchanged.


## Detection Resistance

- **No kernel callbacks** `CmCallback`, object callbacks, and notify routines are all enumerated by EAC/BE. None are registered.
- **No SSDT hooks** the EFI hook targets an unexported internal function absent from the SSDT dispatch table.
- **No driver object** loaded via kdmapper, invisible to `PsLoadedModuleList` and `ZwQuerySystemInformation(SystemModuleInformation)`.
- **PatchGuard safe** all patches are data writes or hooks on non-exported internal functions. No kernel code sections modified.
- **MDL technique** standard kernel pattern used by legitimate components. Pages remain `MdlMappingNoExecute`; only the separately allocated trampoline pool is executable.
- **Double-load guards** a second kdmapper run detects already-patched state and skips re-hooking, preventing broken trampoline chains that cause BSOD.


## Project Structure

```
SecurebootSpoof/
├── entry/
│   └── main.cpp          # DriverEntry calls RegInit + FirmwareInit
├── firmware/
│   ├── firmware.h
│   └── firmware.cpp      # Class 145 patch, SharedUserData, EFI hook
├── registry/
│   ├── registry.h
│   └── registry.cpp      # Registry writes
└── log/
    └── log.h             # DbgPrintEx wrapper
```


## Usage

1. Build with the WDK (Windows Driver Kit) targeting x64
2. Map with [kdmapper](https://github.com/TheCruZ/kdmapper)
3. Verify with DbgView (`DPFLTR_IHVDRIVER_ID` at error level) and:

```powershell
Confirm-SecureBootUEFI
```

```powershell
Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled
```

```powershell
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class SB {
    [DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, ref int ret);
}
"@
$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
$ret = 0
[SB]::NtQuerySystemInformation(145, $buf, 16, [ref]$ret) | Out-Null
$e = [System.Runtime.InteropServices.Marshal]::ReadByte($buf, 0)
$c = [System.Runtime.InteropServices.Marshal]::ReadByte($buf, 1)
"SecureBootEnabled=$e  SecureBootCapable=$c"
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
```


## Requirements

- Windows 10/11 x64
- kdmapper (or equivalent manual mapper)
- WDK for building


## Contact

- **Discord** `.baseaddress`
- **Blog / Research** [hollowsec.xyz](https://hollowsec.xyz)

---

for educational and research purposes.
