#pragma once

#include <Windows.h>
#include <iostream>
#include <vector>
#include <Psapi.h>
#include <algorithm>
#include "Ntdll.hpp"

inline SYSTEM_PROCESS_INFORMATION* FindProcess(const wchar_t* ModName) {
    SYSTEM_PROCESS_INFORMATION* Processes = (SYSTEM_PROCESS_INFORMATION*)malloc(0x400000);
    SYSTEM_PROCESS_INFORMATION* Ret = NULL;
    SYSTEM_PROCESS_INFORMATION* Current;
    goto Start;
End:
    return Ret;
Start:

    if ((DWORD)NtF("NtQuerySystemInformation")(SystemProcessInformation, Processes, 0x400000, NULL) != 0) { goto End; };

    Current = Processes;
    while (Current->NextOffset) {
        if (Current->ImageName.Buffer != 0) {
            if (wcscmp(Current->ImageName.Buffer, ModName) == 0) {
                Ret = Current;
                goto End;
            }
        }
        Current = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)Current + Current->NextOffset);
    }
    goto End;
}

inline MODULEINFO FindModule(HANDLE Handle, const char* ModuleName) {
    char Buffer[256];
    MEMORY_BASIC_INFORMATION MemInfo;

    for (PVOID Cur = nullptr; VirtualQueryEx(Handle, Cur, &MemInfo, sizeof(MemInfo)); Cur = static_cast<PVOID>(static_cast<BYTE*>(Cur) + MemInfo.RegionSize)) {
        if (GetModuleBaseName(Handle, static_cast<HMODULE>(Cur), Buffer, sizeof(Buffer)) && strcmp(Buffer, ModuleName) == 0) {
            MODULEINFO Info;
            GetModuleInformation(Handle, static_cast<HMODULE>(Cur), &Info, sizeof(Info));

            return Info;
        }
    }

    return { nullptr, 0, nullptr };
}

inline BOOL SetPrivilege(const wchar_t* Privilege, DWORD Attributes) {
    HANDLE Token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token))
        return FALSE;

    TOKEN_PRIVILEGES Priv;
    if (!LookupPrivilegeValueW(nullptr, Privilege, &Priv.Privileges[0].Luid))
        return FALSE;

    Priv.PrivilegeCount = 1;
    Priv.Privileges[0].Attributes = Attributes;

    if (!AdjustTokenPrivileges(Token, FALSE, &Priv, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;

    return TRUE;
}