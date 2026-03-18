#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string>
#include <vector>
#include <Windows.h>
#include <mutex>
#include <wintrust.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <algorithm>
#include <fstream>
#include "fnv1a.h"
#pragma comment(lib, "Wintrust.lib")
using NtAllocateVirtualMemory = NTSTATUS(NTAPI*)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);

using NtTerminateProcess = NTSTATUS(NTAPI*)(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus);

typedef DWORD(WINAPI* ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown
);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

namespace memory
{
	inline uintptr_t get_module_handle(const uint64_t mod_name, const uint64_t process = GetCurrentProcessId())
	{
		auto tries = 0;
		do
		{
			MODULEENTRY32 entry;
			entry.dwSize = sizeof(MODULEENTRY32);

			const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process);

			if (Module32First(snapshot, &entry))
				while (Module32Next(snapshot, &entry))
				{
					std::wstring name = entry.szModule;
					std::string szname(name.begin(), name.end());
					std::ranges::transform(szname, szname.begin(), ::tolower);
					if (fnv1a::rt(szname.c_str()) == mod_name)
					{
						CloseHandle(snapshot);
						return reinterpret_cast<uintptr_t>(entry.hModule);
					}
				}

			CloseHandle(snapshot);
		} while (tries++ < 10);
		return 0;
	}

	inline uint8_t* find_sig(const uint32_t offset, const char* signature, const uint32_t range = 0u)
	{
		static auto pattern_to_bytes = [](const char* pattern) -> std::vector<int>
			{
				auto bytes = std::vector<int32_t>{};
				const auto start = const_cast<char*>(pattern);
				const auto end = const_cast<char*>(pattern) + strlen(pattern);

				for (auto current = start; current < end; ++current)
				{
					if (*current == '?')
					{
						current++;

						if (*current == '?')
							current++;

						bytes.push_back(-1);
					}
					else
						bytes.push_back(static_cast<int32_t>(strtoul(current, &current, 0x10)));
				}

				return bytes;
			};

		const auto scan_bytes = reinterpret_cast<std::uint8_t*>(offset);
		auto pattern_bytes = pattern_to_bytes(signature);
		const auto s = pattern_bytes.size();
		const auto d = pattern_bytes.data();

		for (auto i = 0ul; i < range - s; ++i)
		{
			auto found = true;

			for (auto j = 0ul; j < s; ++j)
				if (scan_bytes[i + j] != d[j] && d[j] != -1)
				{
					found = false;
					break;
				}

			if (found)
				return &scan_bytes[i];
		}

		return nullptr;
	}

	inline uint64_t rva_2_offset(const uint64_t rva, PIMAGE_NT_HEADERS nt_headers, const bool in_memory = false)
	{
		if (rva == 0 || !in_memory)
			return rva;

		auto sec = IMAGE_FIRST_SECTION(nt_headers);
		for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
		{
			if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize)
				break;
			sec++;
		}

		return rva - sec->VirtualAddress + sec->PointerToRawData;
	}

	__forceinline uintptr_t get_proc_address(const uintptr_t module, const uint64_t function, const bool in_memory = false)
	{
		const auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
		if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) {
			return 0;
		}

		const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(dos_headers->e_lfanew + module);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
			return 0;
		}

		const auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
			rva_2_offset(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, nt_headers, in_memory) + module
		);

		const auto names = reinterpret_cast<uint32_t*>(rva_2_offset(exports->AddressOfNames, nt_headers, in_memory) + module);

		auto ordinal_index = static_cast<uint32_t>(-1);
		for (uint32_t i = 0; i < exports->NumberOfFunctions; i++) {
			const auto function_name = reinterpret_cast<const char*>(rva_2_offset(names[i], nt_headers, in_memory) + module);
			if (fnv1a::rt(function_name) == function)
			{
				ordinal_index = i;
				break;
			}

			std::string szname(function_name);
			std::ranges::transform(szname, szname.begin(), ::tolower);
			if (fnv1a::rt(szname.c_str()) == function)
			{
				ordinal_index = i;
				break;
			}
		}

		if (ordinal_index > exports->NumberOfFunctions)
			return 0;

		const auto ordinals = reinterpret_cast<uint16_t*>(rva_2_offset(exports->AddressOfNameOrdinals, nt_headers, in_memory) + module);
		const auto addresses = reinterpret_cast<uint32_t*>(rva_2_offset(exports->AddressOfFunctions, nt_headers, in_memory) + module);
		return rva_2_offset(addresses[ordinals[ordinal_index]], nt_headers, in_memory) + module;
	}

	__forceinline uintptr_t get_proc_address(const uintptr_t module, std::string function, const bool in_memory = false)
	{
		const auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
		if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE) {
			return 0;
		}

		const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(dos_headers->e_lfanew + module);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
			return 0;
		}

		const auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
			rva_2_offset(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, nt_headers, in_memory) + module
			);

		const auto names = reinterpret_cast<uint32_t*>(rva_2_offset(exports->AddressOfNames, nt_headers, in_memory) + module);

		auto ordinal_index = static_cast<uint32_t>(-1);
		for (uint32_t i = 0; i < exports->NumberOfFunctions; i++) {
			const auto function_name = reinterpret_cast<const char*>(rva_2_offset(names[i], nt_headers, in_memory) + module);
			if (function == function_name)
			{
				ordinal_index = i;
				break;
			}
		}

		if (ordinal_index > exports->NumberOfFunctions)
			return 0;

		const auto ordinals = reinterpret_cast<uint16_t*>(rva_2_offset(exports->AddressOfNameOrdinals, nt_headers, in_memory) + module);
		const auto addresses = reinterpret_cast<uint32_t*>(rva_2_offset(exports->AddressOfFunctions, nt_headers, in_memory) + module);
		return rva_2_offset(addresses[ordinals[ordinal_index]], nt_headers, in_memory) + module;
	};

	inline std::mutex imp_mutex;

	template <uint64_t module, uint64_t function>
	inline void* import() {
		std::lock_guard l(imp_mutex);
		auto pmod = get_module_handle(module);
		if (!pmod) {
			return nullptr;
		}

		static void* fn = reinterpret_cast<void*>(get_proc_address(pmod, function, false));

		return fn;
	}
}

#define imp(module, name) (reinterpret_cast<decltype(&(name))>(memory::import<fnv1a::ct(module), fnv1a::ct(#name)>()))
#define import(module, name) (reinterpret_cast<name>(memory::import<fnv1a::ct(module), fnv1a::ct(#name)>()))

#pragma once
//#define _ALLOW_MONITOR

#define IS_ADDRESS_NOT_FOUND -1
#define IS_CALLBACK_KILL_FAILURE -2
#define IS_INTEGRITY_STUB_FAILURE -3
#define IS_MODULE_NOT_FOUND -4
#define IS_ALLOCATION_FAILURE -5
#define IS_INIT_NOT_APPLIED -6
#define IS_SUCCESS 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)



inline HINSTANCE hSubsystemInstances[2];

class inline_syscall
{

public:

	inline_syscall();
	void unload();
	void callback();

	void set_error(int error_code) {
		last_error = error_code;
	}

	int get_error() {
		return last_error;
	}

	bool is_init() {
		return initialized;
	}

	UCHAR* get_stub() {
		return syscall_stub;
	}


	template <typename returnType, typename ...args>
	returnType invoke(LPCSTR ServiceName, args... arguments);

private:
	int last_error;
	bool initialized;
	UCHAR* syscall_stub;

	typedef NTSTATUS __stdcall pNtSetInformationProcess(
		HANDLE ProcessHandle,
		PROCESS_INFORMATION_CLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength
	);

	struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	{
		ULONG Version;
		ULONG Reserved;
		PVOID Callback;
	};
};

inline inline_syscall inliner;
#define syscall(name, ...) inliner.invoke<NTSTATUS>(#name, __VA_ARGS__)
namespace memory
{
	inline void protect_mem(void* addr, const uint32_t len, const DWORD new_protect, DWORD& old_protect)
	{
		auto target = addr;
		auto target_len = static_cast<uint64_t>(len);
		syscall(NtProtectVirtualMemory, HANDLE(-1), &target, &target_len, new_protect, &old_protect);
	}

	inline void* alloc_mem(const uint64_t len)
	{
		auto target_len = len;
		void* ret = nullptr;
		import( "ntdll.dll", NtAllocateVirtualMemory ,  HANDLE(-1), &ret, nullptr, &target_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		return ret;
	}
}

namespace Protection {
	inline std::mutex Mutex;
	void Crash();
	void AddMutex();
	void CheckDrivers();
	void VmwareChecker();
	void ProcessChecker();
	void CheckIsDebugger();
	bool FindProcess(std::string szName);
	NTSTATUS CreateThread(PHANDLE pOutThreadHandle, HANDLE hProcess, PVOID pStartAddress, PVOID pArgument);

	void Checker();
	void CheckerThread();

	void Setup();
}