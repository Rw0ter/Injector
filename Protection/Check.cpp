#include <Windows.h>
#include <cstdint>
#include "Check.h"
#include "Protection.hpp"
#include "../utils/xor.h"

static bool IsExecutable(void* pAddress) {
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(pAddress, &mi, sizeof(mi));
    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}

static bool IsValidExecutable(void* pAddress) {
    if (!IsExecutable(pAddress) || !IsExecutable(IsValidExecutable)) {
        return false;
    }

    uint8_t nFirstByte = *reinterpret_cast<uint8_t*>(pAddress);
    if (nFirstByte == 0xE8 || nFirstByte == 0xE9 || nFirstByte == 0xCC || nFirstByte == 0x90) {
        return false;
    }

    return true;
}

void CompareHardwareFunction() {
    if (!IsValidExecutable(reinterpret_cast<void*>(VirtualAlloc))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(VirtualProtect))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(VirtualQuery))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(CreateFileW))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(DeviceIoControl))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(CloseHandle))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(LoadLibraryA))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(LoadLibraryW))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(GetProcAddress))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(GetCurrentProcess))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(GetCurrentProcessId))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(GetCurrentThreadId))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(SetWinEventHook))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(UnhookWinEvent))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(GetWindowThreadProcessId))) {
        Protection::Crash();
    }


    if (!IsValidExecutable(reinterpret_cast<void*>(memset))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(CompareHardwareFunction))) {
        Protection::Crash();
    }

    if (!IsValidExecutable(reinterpret_cast<void*>(Protection::CheckerThread))) {
        Protection::Crash();
    }
    if (!IsValidExecutable(reinterpret_cast<void*>(Protection::Checker))) {
        Protection::Crash();
    }



}