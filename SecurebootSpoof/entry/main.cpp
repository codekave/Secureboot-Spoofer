#include <ntddk.h>
#include "log.h"
#include "registry.h"
#include "firmware.h"

// made by codecave
// discord - .baseaddress
// website https://hollowsec.xyz/

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
    NTSTATUS st = RegInit();
    if (!NT_SUCCESS(st))
        LOG("RegInit: 0x%X\n", st);

    st = FirmwareInit();
    if (!NT_SUCCESS(st))
        LOG("FirmwareInit: 0x%X\n", st);

    return STATUS_SUCCESS;
}
