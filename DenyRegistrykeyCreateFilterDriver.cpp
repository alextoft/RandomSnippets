#include <ntddk.h>

// Define the registry keys to block
const UNICODE_STRING blockedKeys[] = {
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Example1"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Example2"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Example3"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Example4"),
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Example5")
};

// Registry callback function
void RegistryCallback(_In_ REG_NOTIFY_CLASS notifyClass, _In_ PVOID context) {
    PREG_CREATE_KEY_INFORMATION createInfo = (PREG_CREATE_KEY_INFORMATION)context;
    if (notifyClass == RegNtPreCreateKey && createInfo != NULL) {
        for (int i = 0; i < ARRAYSIZE(blockedKeys); i++) {
            if (RtlEqualUnicodeString(&createInfo->CompleteName, &blockedKeys[i], TRUE)) {
                createInfo->Status = STATUS_ACCESS_DENIED;
                createInfo->Disposition = REG_OPENED_EXISTING_KEY;
                break;
            }
        }
    }
}

// Driver entry point
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Register the registry callback function
    PVOID cookie;
    NTSTATUS status = CmRegisterCallbackEx(RegistryCallback, &blockedKeys[0], DriverObject, NULL, &cookie, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}
