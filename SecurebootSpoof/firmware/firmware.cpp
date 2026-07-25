#include "firmware.h"
#include "log.h"
#include <ntimage.h>

// {8be4df61-93ca-11d2-aa0d-00e098032b8c}
static const GUID g_EfiGlobal = {
    0x8be4df61, 0x93ca, 0x11d2,
    { 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c }
};

// {f0a30bc7-af08-4556-99c4-001009c93a44}
static const GUID g_EfiSecureBootEnable = {
    0xf0a30bc7, 0xaf08, 0x4556,
    { 0x99, 0xc4, 0x00, 0x10, 0x09, 0xc9, 0x3a, 0x44 }
};

struct EfiVarEntry {
    const wchar_t* name;
    const GUID*    guid;
    UCHAR          value;
};


static const EfiVarEntry kEfiOverrides[] = {
    { L"SecureBoot",       &g_EfiGlobal,           1 }, // SecureBoot active
    { L"SetupMode",        &g_EfiGlobal,           0 }, // keys enrolled, not in setup
    { L"AuditMode",        &g_EfiGlobal,           0 }, // not in audit mode
    { L"DeployedMode",     &g_EfiGlobal,           1 }, // fully deployed
    { L"SecureBootEnable", &g_EfiSecureBootEnable, 1 }, // enable var
};

typedef NTSTATUS(NTAPI* FnQueryFirmwareEnv)(
    PUNICODE_STRING VariableName,
    LPGUID          VendorGuid,
    PVOID           Value,
    PULONG          ValueLength,
    PULONG          Attributes);

static FnQueryFirmwareEnv g_Orig     = nullptr;
static PMDL               g_Mdl      = nullptr;
static UCHAR              g_OrigBytes[12] = {};

static NTSTATUS NTAPI FirmwareHook(
    PUNICODE_STRING VariableName,
    LPGUID          VendorGuid,
    PVOID           Value,
    PULONG          ValueLength,
    PULONG          Attributes)
{
    if (VariableName && VendorGuid && Value && ValueLength) {
        for (ULONG i = 0; i < ARRAYSIZE(kEfiOverrides); i++) {
            if (RtlCompareMemory(VendorGuid, kEfiOverrides[i].guid, sizeof(GUID)) != sizeof(GUID))
                continue;
            UNICODE_STRING target;
            RtlInitUnicodeString(&target, kEfiOverrides[i].name);
            if (!RtlEqualUnicodeString(VariableName, &target, TRUE))
                continue;
            if (*ValueLength < 1)
                break;
            *(PUCHAR)Value = kEfiOverrides[i].value;
            *ValueLength   = 1;
            if (Attributes) *Attributes = 0x6;
            LOG("EFI %wZ -> %u\n", VariableName, kEfiOverrides[i].value);
            return STATUS_SUCCESS;
        }
    }
    return g_Orig(VariableName, VendorGuid, Value, ValueLength, Attributes);
}

static PVOID ScanPattern(PUCHAR base, ULONG size, const UCHAR* pat, const char* mask, ULONG len) {
    for (ULONG i = 0; i + len <= size; i++) {
        bool ok = true;
        for (ULONG j = 0; j < len; j++)
            if (mask[j] == 'x' && base[i + j] != pat[j]) { ok = false; break; }
        if (ok) return base + i;
    }
    return nullptr;
}

static PVOID FindNtBase(PVOID anyNtAddr) {
    PUCHAR target = (PUCHAR)anyNtAddr;
    PUCHAR p = (PUCHAR)((ULONG_PTR)anyNtAddr & ~(ULONG_PTR)0xFFF);
    for (int i = 0; i < 0x10000; i++, p -= 0x1000) {
        if (!MmIsAddressValid(p)) continue;
        if (*(USHORT*)p != 0x5A4D) continue;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)p;
        if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x1000) continue;
        if (!MmIsAddressValid(p + dos->e_lfanew)) continue;
        if (*(ULONG*)(p + dos->e_lfanew) != 0x00004550) continue;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(p + dos->e_lfanew);
        if (target >= p && target < p + nt->OptionalHeader.SizeOfImage)
            return p;
    }
    return nullptr;
}

static NTSTATUS PatchSecureBootGlobal(PVOID ntBase) {
    if (!ntBase) return STATUS_NOT_FOUND;
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)ntBase;
    PIMAGE_NT_HEADERS64 nt  = (PIMAGE_NT_HEADERS64)((PUCHAR)ntBase + dos->e_lfanew);
    ULONG imgSz = nt->OptionalHeader.SizeOfImage;

    // 8A 05 ?? ?? ?? ??  mov al,  [rip+d]   <- SecureBootEnabled bit
    // 24 01 88 02        and al,1  mov [rdx],al
    // 8B 05 ?? ?? ?? ??  mov eax, [rip+d]   <- same global, SecureBootCapable
    // C1 E8 03 24 01 88 42 01  shr/and/mov [rdx+1]
    static const UCHAR kSig[] = {
        0x8A, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x01, 0x88, 0x02,
        0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0xC1, 0xE8, 0x03, 0x24, 0x01, 0x88, 0x42, 0x01
    };
    static const char kMask[] = "xx????xxxxxx????xxxxxxxx";

    PUCHAR hit = (PUCHAR)ScanPattern((PUCHAR)ntBase, imgSz, kSig, kMask, 24);
    if (!hit) { LOG("class145 sig not found\n"); return STATUS_NOT_FOUND; }

    INT32  disp   = *(INT32*)(hit + 2);
    PULONG pFlags = (PULONG)(hit + 6 + disp);
    if (!MmIsAddressValid(pFlags)) { LOG("class145 addr invalid\n"); return STATUS_UNSUCCESSFUL; }

    if ((*pFlags & 0x09) == 0x09) { LOG("class145 already patched\n"); return STATUS_SUCCESS; }

    *pFlags |= 0x09;
    LOG("class145 flags -> 0x%X\n", *pFlags);
    return STATUS_SUCCESS;
}

static PVOID FindNtQuerySystemEnvironmentValueEx(PVOID ntBase) {
    if (!ntBase) return nullptr;
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)ntBase;
    PIMAGE_NT_HEADERS64 nt  = (PIMAGE_NT_HEADERS64)((PUCHAR)ntBase + dos->e_lfanew);
    ULONG imgSz = nt->OptionalHeader.SizeOfImage;

    // 40 53 56 57 41 54 41 55 41 56 41 57  push rbx/rsi/rdi/r12/r13/r14/r15
    // 48 81 EC 80 00 00 00                 sub rsp, 0x80
    // 48 8B 05 ?? ?? ?? ??                 mov rax, [rip+d]  (cookie)
    // 48 33 C4                             xor rax, rsp
    // 48 89 44 24 78                       mov [rsp+0x78], rax
    // 4D 8B E1  4D 8B F8  4C 8B F2  48 8B F9  mov r12,r9 / r13,r8 / r14,rdx / rdi,rcx
    static const UCHAR kSig[] = {
        0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x33, 0xC4,
        0x48, 0x89, 0x44, 0x24, 0x78,
        0x4D, 0x8B, 0xE1,
        0x4D, 0x8B, 0xF8,
        0x4C, 0x8B, 0xF2,
        0x48, 0x8B, 0xF9
    };
    static const char kMask[] = "xxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxx";

    return ScanPattern((PUCHAR)ntBase, imgSz, kSig, kMask, 46);
}

NTSTATUS FirmwareInit() {
    UNICODE_STRING anchorName;
    RtlInitUnicodeString(&anchorName, L"ExAllocatePool2");
    PVOID anchor = MmGetSystemRoutineAddress(&anchorName);

    PVOID ntBase = FindNtBase(anchor);
    LOG("ntBase: %p\n", ntBase);

    NTSTATUS stPatch = PatchSecureBootGlobal(ntBase);
    if (!NT_SUCCESS(stPatch)) LOG("class145 patch failed: 0x%X\n", stPatch);

    SharedUserData->DbgSecureBootEnabled = 1;
    LOG("SharedUserData patched\n");

    PVOID fn = FindNtQuerySystemEnvironmentValueEx(ntBase);
    if (!fn) {
        LOG("NtQuerySystemEnvironmentValueEx not found\n");
        return NT_SUCCESS(stPatch) ? STATUS_SUCCESS : stPatch;
    }

    if (*(USHORT*)fn == 0xB848) {
        LOG("EFI hook already present\n");
        return NT_SUCCESS(stPatch) ? STATUS_SUCCESS : stPatch;
    }

    // 48 B8 <imm64> FF E0 — mov rax, imm64; jmp rax
    PUCHAR tramp = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, 24, 'FWsb');
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(g_OrigBytes, fn, 12);
    RtlCopyMemory(tramp, g_OrigBytes, 12);
    PUCHAR jb = tramp + 12;
    jb[0] = 0x48; jb[1] = 0xB8;
    *(PVOID*)(jb + 2) = (PVOID)((PUCHAR)fn + 12);
    jb[10] = 0xFF; jb[11] = 0xE0;
    g_Orig = (FnQueryFirmwareEnv)tramp;

    g_Mdl = IoAllocateMdl(fn, 12, FALSE, FALSE, nullptr);
    if (!g_Mdl) { ExFreePool(tramp); return STATUS_INSUFFICIENT_RESOURCES; }

    MmBuildMdlForNonPagedPool(g_Mdl);
    PVOID rw = MmMapLockedPagesSpecifyCache(
        g_Mdl, KernelMode, MmNonCached, nullptr, FALSE,
        NormalPagePriority | MdlMappingNoExecute);
    if (!rw) {
        IoFreeMdl(g_Mdl); g_Mdl = nullptr;
        ExFreePool(tramp);
        return STATUS_UNSUCCESSFUL;
    }

    // 48 B8 <hook addr> FF E0
    UCHAR detour[12] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
    *(PVOID*)(detour + 2) = FirmwareHook;
    RtlCopyMemory(rw, detour, 12);
    MmUnmapLockedPages(rw, g_Mdl);

    LOG("EFI hook @ %p\n", fn);
    return STATUS_SUCCESS;
}

void FirmwareCleanup() {
    if (!g_Mdl || !g_Orig) return;
    PVOID rw = MmMapLockedPagesSpecifyCache(
        g_Mdl, KernelMode, MmNonCached, nullptr, FALSE,
        NormalPagePriority | MdlMappingNoExecute);
    if (rw) {
        RtlCopyMemory(rw, g_OrigBytes, 12);
        MmUnmapLockedPages(rw, g_Mdl);
    }
    IoFreeMdl(g_Mdl);
    g_Mdl = nullptr;
    LOG("EFI hook removed\n");
}
