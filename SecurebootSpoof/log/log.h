#pragma once
#include <ntddk.h>
#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[SBSpoof] " fmt, ##__VA_ARGS__)
