#include <vector>
#include <string>
#include "Inject.h"
#include "../Image/Cheat.h"
#include "../utils/Dynamic Instruction.hpp"
#include "../Compiler/Compiler.hpp"
#include "../utils/Export Spoof.h"
#include "../Protection/Protection.hpp"
/*
	!!!IMPORTANT!!! for this to work correctly please disable Security Check (/GS-)
*/
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

//keep this 
#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall shellcode()
{
    DYNAMIC_INSTRUCTION

	uintptr_t base = 0x15846254168; // random
	uintptr_t pointer_address = 0x24856841253; // random

	memset((void*)pointer_address, 0x69, 1);

	BYTE* pBase = (BYTE*)base;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = LI_FN(LoadLibraryA).get();
	auto _GetProcAddress = LI_FN(GetProcAddress).get();
	auto _RtlAddFunctionTable = LI_FN(RtlAddFunctionTable).get();

	auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved)>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG64(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}


	//SEH SUPPORT
	auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (excep.Size) {
		if (!_RtlAddFunctionTable(
			reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
			excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, 0);
}

static bool IsValidateExecutableImage(void* pImageBase) {
    DYNAMIC_INSTRUCTION
        const PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    const PIMAGE_NT_HEADERS64 pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(pImageBase) + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    return true;
}

bool Inject::inject_module_from_memory_to_process_by_name(const wchar_t* process_name)
{
    DYNAMIC_INSTRUCTION

        Protection::Checker();

    int target_process_id = utils::get_pid_from_name(process_name);

    if (!target_process_id)
    {
        SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Could not found cs2.exe Process!\n"));
        return false;
    }

    auto target_process_hwnd = utils::get_hwnd_of_process_id(target_process_id);
    auto nt_dll = LI_FN(LoadLibraryA).forwarded_safe_cached()(xor_a("ntdll.dll"));
    auto thread_id = LI_FN(GetWindowThreadProcessId).forwarded_safe_cached()(target_process_hwnd, 0);

    Protection::Checker();
    SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Analyze Neverlose Spoofer v2.6 Data.\n"));
    SPOOF_CALL(Sleep)(1000);

    std::string szCheatData(reinterpret_cast<char*>(arrCheatData), sizeof(arrCheatData));
    std::vector<uint8_t> vecLibraryBytes = CCompiler::DecompileU8(szCheatData);

    while (!IsValidateExecutableImage(vecLibraryBytes.data())) {
        vecLibraryBytes = CCompiler::DecompileU8(szCheatData);
        if (IsValidateExecutableImage(vecLibraryBytes.data())) {
            break;
        }
    }

    Protection::Checker();
    uint8_t* dll_buffer = vecLibraryBytes.data();

    if (!dll_buffer){
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_buffer;
    PIMAGE_NT_HEADERS nt_header =
        (PIMAGE_NT_HEADERS)(dll_buffer + dos->e_lfanew);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    struct DataDirInfo {
        DWORD VirtualAddress;
        DWORD Size;
    };
    DataDirInfo pe_directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = { 0 };
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        pe_directories[i].VirtualAddress = nt_header->OptionalHeader.DataDirectory[i].VirtualAddress;
        pe_directories[i].Size = nt_header->OptionalHeader.DataDirectory[i].Size;
    }
    
    DWORD nt_header_offset = dos->e_lfanew;
    DWORD size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;

    auto driver = std::make_unique<Driver>(
        xor_w(L"\\\\.\\{zxchigfysordfds-dsyfgsydfzxhcgzxjhgvsdf}"),
        target_process_id
    );

    if (!driver || driver->driver_handle == INVALID_HANDLE_VALUE)
    {
        SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Driver open failed\n"));
        return false;   
    }

    const SIZE_T image_size = nt_header->OptionalHeader.SizeOfImage;
    SIZE_T alloc_size = (image_size + 0xFFF) & ~0xFFF;

    uintptr_t allocated_base = 0;

    for (size_t i = 0; i < 32; i++)
    {
        if(allocated_base)
			break;

        allocated_base = driver->allocate_virtual_memory(
            alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Sleep(100);
    }

    if (!allocated_base)
    {
        SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Failed allocate memory: 0xA0000078\n"));
        return false;
    }

    driver->protect_virtual_memory(allocated_base, image_size, PAGE_EXECUTE_READWRITE);

    if (!driver->write_memory(allocated_base, (uintptr_t)dll_buffer, 0x1000))
    {
        SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Failed to write memory: 0xB0000091\n"));
        return false;
    }

    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);

    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header++)
    {
        if (section_header->SizeOfRawData == 0)
            continue;

        uintptr_t dest = allocated_base + section_header->VirtualAddress;
        uintptr_t src = (uintptr_t)dll_buffer + section_header->PointerToRawData;

        bool ok = false;
        for (int r = 0; r < 5; r++)
        {
            if (driver->write_memory(dest, src, section_header->SizeOfRawData))
            {
                ok = true;
                break;
            }
            Sleep(30);
        }

        if (!ok)
        {
            SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Failed to write memory: 0xC0000721\n"));
            return false;
        }
    }

    

    SPOOF_CALL(LI_FN(printf).forwarded_safe_cached())(xor_a("Successfully mapped sections from memory!\n"));

    memset(vecLibraryBytes.data(), 0, vecLibraryBytes.size());
    vecLibraryBytes.clear();
    dll_buffer = nullptr;

    uintptr_t allocated_shellcode =
        driver->allocate_virtual_memory(0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    uintptr_t shellcode_value =
        driver->allocate_virtual_memory(sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    uintptr_t allocatedbase_offset =
        (uintptr_t)utils::find_pattern("\x68\x41\x25\x46\x58\x01\x00\x00", "xxxxxx??")
        - (uintptr_t)&shellcode;

    uintptr_t allocatedvalue_offset =
        (uintptr_t)utils::find_pattern("\x53\x12\x84\x56\x48\x02\x00\x00", "xxxxxx??")
        - (uintptr_t)&shellcode;

    auto sc_len = utils::get_function_length(&shellcode);
    uintptr_t localsc = (uintptr_t)LI_FN(VirtualAlloc).forwarded_safe_cached()(0, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    memcpy((void*)localsc, &shellcode, sc_len);

    *(uintptr_t*)(localsc + allocatedbase_offset) = allocated_base;
    *(uintptr_t*)(localsc + allocatedvalue_offset) = shellcode_value;

    driver->write_memory(allocated_shellcode, localsc, sc_len);

    auto hook = SPOOF_CALL(LI_FN(SetWinEventHook).forwarded_safe_cached())(EVENT_MIN, EVENT_MAX, nt_dll,
        (WINEVENTPROC)allocated_shellcode,
        target_process_id, thread_id, WINEVENT_INCONTEXT);

    while (true)
    {
        int flag = 0;
        driver->read_memory(shellcode_value, (uintptr_t)&flag, sizeof(flag));

        if (flag == 0x69)
        {
            SPOOF_CALL(LI_FN(UnhookWinEvent).forwarded_safe_cached())(hook);

            SPOOF_CALL(Sleep)(3000);

            uint8_t* empty_buffer = new uint8_t[0x1000];
            memset(empty_buffer, 0, 0x1000);

            driver->write_memory(allocated_base, (uintptr_t)empty_buffer, (int)size_of_headers);

            if (pe_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {
                DWORD export_size = pe_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                uint8_t* export_buffer = new uint8_t[export_size];
                memset(export_buffer, 0, export_size);
                driver->write_memory(allocated_base + pe_directories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, 
                    (uintptr_t)export_buffer, (int)export_size);
                delete[] export_buffer;
            }

            if (pe_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0) {
                DWORD debug_size = pe_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                uint8_t* debug_buffer = new uint8_t[debug_size];
                memset(debug_buffer, 0, debug_size);
                driver->write_memory(allocated_base + pe_directories[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, 
                    (uintptr_t)debug_buffer, (int)debug_size);
                delete[] debug_buffer;
            }

            if (pe_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
                DWORD reloc_size = pe_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                uint8_t* reloc_buffer = new uint8_t[reloc_size];
                memset(reloc_buffer, 0, reloc_size);
                driver->write_memory(allocated_base + pe_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, 
                    (uintptr_t)reloc_buffer, (int)reloc_size);
                delete[] reloc_buffer;
            }


            if (pe_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size > 0) {
                DWORD bound_size = pe_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
                uint8_t* bound_buffer = new uint8_t[bound_size];
                memset(bound_buffer, 0, bound_size);
                driver->write_memory(allocated_base + pe_directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, 
                    (uintptr_t)bound_buffer, (int)bound_size);
                delete[] bound_buffer;
            }

            driver->protect_virtual_memory(allocated_base, 0x1000, PAGE_NOACCESS);

            driver->write_memory(allocated_shellcode, (uintptr_t)empty_buffer, 0x1000);
            driver->protect_virtual_memory(allocated_shellcode, 0x1000, PAGE_NOACCESS);

            delete[] empty_buffer;

            LI_FN(VirtualFree).forwarded_safe_cached()((void*)localsc, 0, MEM_RELEASE);

            return true;
        }
    }

    return false;
}

