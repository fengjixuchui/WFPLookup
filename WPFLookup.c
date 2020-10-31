// WPFLookup.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <windows.h>
#include <fwpmu.h>

int main(int argc, char** argv)
{
    DWORD result = ERROR_SUCCESS;
    if (argc != 2) {
        printf("Usage: %s <filterID>\n", argv[0]);
        return 1;
    }

    // Get ID of filter to lookup
    CHAR* filterString = argv[1];
    UINT64 filterID = strtoll(filterString, 0, 10);
    if (filterID == 0) {
        printf("Usage: %s <filterID>\n", argv[0]);
        return 1;
    }

    // Connect to WFP Engine
    HANDLE engineHandle = NULL;
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (result != ERROR_SUCCESS) {
        printf("FwpmEngineOpen0 failed. Return value: %d.\n", result);
        return 1;
    }

    // Lookup Filter
    FWPM_FILTER0* filter = NULL;
    result = FwpmFilterGetById0(engineHandle, filterID, &filter);
    if (result == FWP_E_FILTER_NOT_FOUND) {
        printf("Filter %s not found\n", filterString);
        return 1;
    }
    else if (result != ERROR_SUCCESS) {
        printf("FwpmFilterGetById0 failed. Return value: %d.\n", result);
        return 1;
    }

    // Loop over the filter's conditions, looking for a protocol condition
    BOOL foundConditional = FALSE;
    for (size_t i = 0; i < filter->numFilterConditions; i++)
    {
        FWPM_FILTER_CONDITION0 filterCondition = filter->filterCondition[i];
        if (IsEqualGUID(&filterCondition.fieldKey, &FWPM_CONDITION_IP_PROTOCOL)) {
            foundConditional = TRUE;
            BYTE protocol = filterCondition.conditionValue.uint8;
            if (protocol == IPPROTO_TCP) {
                printf("Filter %s: TCP\n", filterString);
            }
            else if (protocol == IPPROTO_UDP) {
                printf("Filter %s: UDB\n", filterString);
            }
            else {
                printf("Filter %s: Other(%d)\n", filterString, protocol);
            }
            break;
        }
    }
    if (!foundConditional) {
        printf("No Protocol Conditional\n");
    }
    return 0;
}
