#pragma once

#include <Windows.h>
#include <memory>
#include <vector>
#include <winnt.h>
#include <psapi.h>
#include "TP.hpp"
#include "Utils.hpp"
#include <wininet.h>
#include <sstream>
#pragma comment(lib, "wininet.lib")

inline void* ConvertAddress(const void* address, const void* old_base, const void* new_base) {
    return reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(old_base) + reinterpret_cast<uintptr_t>(new_base)
        );
}

inline MODULEINFO GetCurrentModuleInfo() {
    MODULEINFO modinfo{};
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (hModule) {
        GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(modinfo));
    }
    return modinfo;
}

inline MODULEINFO FindRemoteModule(HANDLE process, const char* module_name) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(process, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            char name[MAX_PATH];
            if (GetModuleBaseNameA(process, hMods[i], name, sizeof(name))) {
                if (_stricmp(name, module_name) == 0) {
                    MODULEINFO info{};
                    GetModuleInformation(process, hMods[i], &info, sizeof(info));
                    return info;
                }
            }
        }
    }
    return { nullptr, 0, nullptr };
}

inline bool AllocateRemoteImage(HANDLE process, const MODULEINFO& local, void*& remote_alloc) {
    remote_alloc = VirtualAllocEx(process, nullptr, local.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_alloc)
        return false;

    if (!WriteProcessMemory(process, remote_alloc, local.lpBaseOfDll, local.SizeOfImage, nullptr)) {
        VirtualFreeEx(process, remote_alloc, 0, MEM_RELEASE);
        return false;
    }
    return true;
}

inline bool ExecuteTPool(HANDLE process, const void* local_base, void* remote_alloc, const void* address_to_call) {
    void* adjusted = ConvertAddress(address_to_call, local_base, remote_alloc);
    return CreateTP(process, adjusted);
}

class CInjection {
public:
    bool Inject(HANDLE process, const void* entry_point) {
        MODULEINFO local = GetCurrentModuleInfo();
        if (!local.lpBaseOfDll || !local.SizeOfImage)
            return false;

        MODULEINFO remote = FindRemoteModule(process, "RobloxPlayerBeta.dll");
        if (!remote.lpBaseOfDll || !remote.SizeOfImage)
            return false;

        void* remote_alloc = nullptr;
        if (!AllocateRemoteImage(process, local, remote_alloc))
            return false;

        return ExecuteTPool(process, local.lpBaseOfDll, remote_alloc, entry_point);
    }
};

inline auto Injection = std::make_unique<CInjection>();

#pragma optimize("\\", off)

void test_print() {
    uintptr_t RobloxBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    auto RbxPrint = reinterpret_cast<void(__fastcall*)(int, const char*, ...)>(RobloxBase + 0x15469F0);
    RbxPrint(0, "test!, no crash!");
}

#pragma optimize("\\", on)
