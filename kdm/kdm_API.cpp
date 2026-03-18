#include "kdm_API.h"
#include "intel_driver.hpp"
#include "kdmapper.hpp"
#include "utils.hpp"
#include "../utils/Dynamic Instruction.hpp"
#include "../Protection/Protection.hpp"

bool MapDriverFromMemory(const std::vector<uint8_t>& sysBuffer)
{
    DYNAMIC_INSTRUCTION

        Protection::Checker();

    if (!NT_SUCCESS(intel_driver::Load()))
        return false;

    NTSTATUS exitCode = 0;

    bool ok = kdmapper::MapDriver(
        (uint8_t*)sysBuffer.data(),
        0, 0,
        false,                // free=false
        true,                 // no copy header
        kdmapper::AllocationMode::AllocatePool,
        false,                // no pass allocation ptr
        nullptr,              // no callback
        &exitCode
    );

    intel_driver::Unload();
    return ok;
}

bool MapDriverFromFile(const std::wstring& sysPath)
{
    std::vector<uint8_t> data;

    if (!kdmUtils::ReadFileToMemory(sysPath, &data))
        return false;

    return MapDriverFromMemory(data);
}
