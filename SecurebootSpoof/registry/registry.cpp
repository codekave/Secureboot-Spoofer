#include "registry.h"
#include "log.h"

static NTSTATUS WriteRegDword(HANDLE hKey, const wchar_t* name, ULONG value) {
    UNICODE_STRING valName;
    RtlInitUnicodeString(&valName, name);
    return ZwSetValueKey(hKey, &valName, 0, REG_DWORD, &value, sizeof(value));
}

static HANDLE OpenOrCreateKey(const wchar_t* path) {
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    HANDLE hKey;
    NTSTATUS st = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) {
        ULONG disp;
        st = ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, nullptr, REG_OPTION_NON_VOLATILE, &disp);
    }
    return NT_SUCCESS(st) ? hKey : nullptr;
}

NTSTATUS RegInit() {
    HANDLE hState = OpenOrCreateKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
    if (!hState) { LOG("reg State open failed\n"); return STATUS_UNSUCCESSFUL; }

    WriteRegDword(hState, L"UEFISecureBootEnabled", 1);
    WriteRegDword(hState, L"SecureBootCapable",     1);
    ZwClose(hState);
    LOG("State: UEFISecureBootEnabled=1, SecureBootCapable=1\n");

    HANDLE hServicing = OpenOrCreateKey(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing");
    if (hServicing) {
        WriteRegDword(hServicing, L"DeviceAttributes", 1);
        ZwClose(hServicing);
        LOG("Servicing: DeviceAttributes=1\n");
    }

    return STATUS_SUCCESS;
}

void RegCleanup() {}
