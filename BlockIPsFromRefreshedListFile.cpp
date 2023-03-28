#include <ntddk.h>
#include <ndis.h>

#define BLOCKED_FILE L"C:\\blocked.txt"

// Define the maximum number of blocked IP addresses
#define MAX_BLOCKED_IPS 100

// Define the blocked IP addresses
ULONG blockedIps[MAX_BLOCKED_IPS];
ULONG numBlockedIps = 0;

// Define the timer object
KTIMER timer;
KDPC timerDpc;

// Define the file object
PFILE_OBJECT fileObject = NULL;

// Define the NDIS filter driver context
typedef struct _FILTER_DEVICE_EXTENSION {
    NDIS_HANDLE filterHandle;
    NDIS_STRING adapterName;
    NDIS_EVENT readEvent;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

// Define the NDIS filter driver receive handler
NDIS_STATUS FilterReceiveNetBufferLists(_In_ NDIS_HANDLE filterModuleContext, _In_ PNET_BUFFER_LIST netBufferLists, _In_ NDIS_PORT_NUMBER portNumber, _In_ ULONG numberOfNetBufferLists, _In_ ULONG receiveFlags) {
    // Get the filter device extension
    PFILTER_DEVICE_EXTENSION filterDeviceExtension = (PFILTER_DEVICE_EXTENSION)filterModuleContext;

    // Loop through the net buffer lists
    for (PNET_BUFFER_LIST netBufferList = netBufferLists; netBufferList != NULL; netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList)) {
        // Loop through the net buffers
        for (PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList); netBuffer != NULL; netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
            // Get the IP header
            PNET_BUFFER_DATA_LENGTH nbDataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
            if (nbDataLength->DataLength < sizeof(IPv4_HEADER)) {
                continue;
            }
            PIPv4_HEADER ipHeader = (PIpv4_HEADER)NET_BUFFER_FIRST_MDL(netBuffer)->MappedSystemVa;

            // Check if the destination IP address is blocked
            for (ULONG i = 0; i < numBlockedIps; i++) {
                if (ipHeader->DestinationAddress == blockedIps[i]) {
                    // Block the TCP connection
                    PTCPIP_NET_BUFFER_LIST_INFO tcpipNetBufferListInfo = TCPIP_GET_NET_BUFFER_LIST_INFO(netBufferList, TcpIpNetBufferListInfo);
                    if (tcpipNetBufferListInfo != NULL) {
                        tcpipNetBufferListInfo->TcpIpChecksumBlocked = TRUE;
                    }
                    break;
                }
            }
        }
    }

    // Pass the net buffer lists to the next filter or the miniport
    return NdisFIndicateReceiveNetBufferLists(filterDeviceExtension->filterHandle, netBufferLists, portNumber, numberOfNetBufferLists, receiveFlags);
}

// Define the timer callback function
VOID TimerCallback(_In_ KDPC *dpc, _In_opt_ PVOID context, _In_opt_ PVOID systemArgument1, _In_opt_ PVOID systemArgument2) {
    // Read the blocked IP addresses from the file
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, BLOCKED_FILE);
    InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS status = ZwCreateFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(status)) {
        FILE_STANDARD_INFORMATION fileInfo;
        status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);
        if (NT_SUCCESS(status)) {
            ULONG fileSize = fileInfo.EndOfFile.LowPart;
            if (fileSize > 0) {
                PVOID fileBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, fileSize, 'IPBL');
                if (fileBuffer != NULL) {
                    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, fileBuffer, fileSize, NULL, NULL);
                    if (NT_SUCCESS(status)) {
                        // Parse the IP addresses from the file
                        ULONG numIps = 0;
                        PCHAR ipString = (PCHAR)fileBuffer;
                        while (ipString < (PCHAR)fileBuffer + fileSize) {
                            ULONG ip = inet_addr(ipString);
                            if (ip != INADDR_NONE) {
                                blockedIps[numIps++] = ip;
                                if (numIps >= MAX_BLOCKED_IPS) {
                                    break;
                                }
                            }
                            ipString += strlen(ipString) + 1;
                        }
                        numBlockedIps = numIps;
                    }
                    ExFreePoolWithTag(fileBuffer, 'IPBL');
                }
            }
        }
        ZwClose(fileHandle);
    }
}

// Define the NDIS filter driver unload handler
VOID FilterUnload(_In_ PDRIVER_OBJECT driverObject) {
    // Cancel the timer
    KeCancelTimer(&timer);

    // Delete the timer DPC
    IoFreeDpc(&timerDpc);

    // Delete the timer object
    KeDeleteTimer(&timer);

    // Close the file object
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }

    // Unregister the NDIS filter driver
    NdisFUnregisterFilterDriver(filterDriverHandle);

    // Free the adapter name buffer
    ExFreePool(filterDeviceExtension.adapterName.Buffer);

    // Delete the filter device extension
    ExFreePool(filterDeviceExtension);
}

// Define the NDIS filter driver attach handler
NDIS_STATUS FilterAttach(_In_ NDIS_HANDLE filterDriverHandle, _In_ NDIS_HANDLE filterAttachParameters) {
    // Get the filter attach parameters
    PNDIS_FILTER_ATTACH_PARAMETERS attachParameters = (PNDIS_FILTER_ATTACH_PARAMETERS)filterAttachParameters;

    // Allocate the filter device extension
    PFILTER_DEVICE_EXTENSION filterDeviceExtension = (PFILTER_DEVICE_EXTENSION)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FILTER_DEVICE_EXTENSION), 'IPBL');
    if (filterDeviceExtension == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    // Initialize the filter device extension
    NdisZeroMemory(filterDeviceExtension, sizeof(FILTER_DEVICE_EXTENSION));
    filterDeviceExtension->filterHandle = attachParameters->FilterHandle;
    filterDeviceExtension->adapterName = attachParameters->BaseMiniportInstanceName;

    // Register the NDIS filter driver receive handler
    NDIS_FILTER_PARTIAL_CHARACTERISTICS filterCharacteristics;
    NdisZeroMemory(&filterCharacteristics, sizeof(filterCharacteristics));
    filterCharacteristics.Header.Type = NDIS_OBJECT_TYPE_FILTER_PARTIAL_CHARACTERISTICS;
    filterCharacteristics.Header.Revision = NDIS_FILTER_PARTIAL_CHARACTERISTICS_REVISION_1;
    filterCharacteristics.Header.Size = NDIS_SIZEOF_FILTER_PARTIAL_CHARACTERISTICS_REVISION_1;
    filterCharacteristics.Flags = 0;
    filterCharacteristics.FilterReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
    NDIS_STATUS status = NdisFSetAttributes(filterDeviceExtension->filterHandle, (NDIS_HANDLE)filterDeviceExtension, (NDIS_HANDLE)NULL, NDIS_FILTER_ATTRIBUTES, (PVOID)&filterCharacteristics, sizeof(filterCharacteristics));
    if (status != NDIS_STATUS_SUCCESS) {
        ExFreePoolWithTag(filterDeviceExtension, 'IPBL');
        return status;
    }

    // Open the blocked IP addresses file
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, BLOCKED_FILE);
    InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = IoCreateFileEx(&fileObject, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK, NULL);
    if (status != STATUS_SUCCESS) {
        NdisFDeregisterFilterDriver(filterDriverHandle);
        ExFreePoolWithTag(filterDeviceExtension, 'IPBL');
        return NDIS_STATUS_FAILURE;
    }

    // Initialize the timer object
    KeInitializeTimer(&timer);
    KeInitializeDpc(&timerDpc, TimerCallback, (PVOID)filterDeviceExtension);

    // Set the timer to fire once per minute
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -600000000; // 1 minute in 100-nanosecond intervals
    KeSetTimerEx(&timer, dueTime, 60000, &timerDpc);

    // Save the filter device extension
    filterDeviceExtension->readEvent = attachParameters->AttachCompleteEvent;
    attachParameters->FilterModuleContext = (PVOID)filterDeviceExtension;

    // Return success
    return NDIS_STATUS_SUCCESS;
}
