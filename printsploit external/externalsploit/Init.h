#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>

#include <Injection/Injection.hpp>
#include <Injection/ThreadPool.hpp>
#include <Injection/Utils.hpp>

int execute_function(const void* entry_point) {
    if (!SetPrivilege(L"SeDebugPrivilege", SE_PRIVILEGE_ENABLED)) {
        printf("Privilege elevation failed\n");
        return 1;
    }
    SetupNTDLL();
    if (!NTDLL) {
        printf("Nt subsystem access denied\n");
        return 1;
    }
    auto* proc_info = FindProcess(L"RobloxPlayerBeta.exe");
    if (!proc_info || !proc_info->ProcessId) {
        printf("Target process not found\n");
        return 1;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_info->ProcessId);
    if (process == INVALID_HANDLE_VALUE || !process) {
        printf("Process access denied\n");
        return 1;
    }
    if (!Injection->Inject(process, entry_point)) {
        printf("Injection failed\n");
        return 1;
    }
    return 0;
}
