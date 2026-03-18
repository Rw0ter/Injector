#include "Protection.hpp"
#include "../utils/Dynamic Instruction.hpp"
#include "../utils/xor.h"
#include "Check.h"
static inline std::atomic_bool isDebuggerPresentPatched{};
inline_syscall::inline_syscall() {

	NTSTATUS Status;
	UINT i;

	initialized = 0;
	syscall_stub = 0;
	last_error = IS_INIT_NOT_APPLIED;

	hSubsystemInstances[0] = GetModuleHandleA(xor_a("ntdll.dll"));
	hSubsystemInstances[1] = GetModuleHandleA(xor_a("win32u.dll"));

	if (!hSubsystemInstances[0]) {
		hSubsystemInstances[0] = LoadLibraryA(xor_a("ntdll.dll"));
	}

	if (!hSubsystemInstances[1]) {
		hSubsystemInstances[1] = LoadLibraryA(xor_a("win32u.dll"));
	}

	for (i = 0; i < 2; i++)
		if (hSubsystemInstances[i] == nullptr)
		{
			last_error = IS_MODULE_NOT_FOUND;
			return;
		}

	syscall_stub = (UCHAR*)VirtualAlloc(NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (syscall_stub == nullptr)
	{
		last_error = IS_CALLBACK_KILL_FAILURE;
		return;
	}


	memcpy(syscall_stub, "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\x0F\x05\xC3", 11);

	callback();
	if (last_error != IS_SUCCESS)
		return;

	last_error = IS_SUCCESS;
	initialized = 1;
}

void inline_syscall::callback() {
	NTSTATUS Status;
	pNtSetInformationProcess* NtSetInformationProcess;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION SyscallCallback;



	NtSetInformationProcess = (pNtSetInformationProcess*)GetProcAddress(hSubsystemInstances[0], xor_a("NtSetInformationProcess"));
	if (NtSetInformationProcess == nullptr)
	{
		inline_syscall::set_error(IS_ADDRESS_NOT_FOUND);
		return;
	}


	//
	//	Disable any callbacks caused by the syscall instruction
	//	( Prevents monitoring of the syscall )
	//
	SyscallCallback.Reserved = 0;
	SyscallCallback.Version = 0;
	SyscallCallback.Callback = NULL;

	Status = NtSetInformationProcess(
		GetCurrentProcess(),
		(PROCESS_INFORMATION_CLASS)40,
		&SyscallCallback,
		sizeof(SyscallCallback));

	if (!NT_SUCCESS(Status))
	{
		inline_syscall::set_error(IS_CALLBACK_KILL_FAILURE);
		return;
	}


	inline_syscall::set_error(IS_SUCCESS);

}

VOID inline_syscall::unload() {

	if (inline_syscall::syscall_stub == nullptr)
		return;

	memset(inline_syscall::syscall_stub, 0, 21);
	VirtualFree(inline_syscall::syscall_stub, 0, MEM_RELEASE);

}

template <typename returnType, typename ...args>
returnType inline_syscall::invoke(LPCSTR ServiceName, args... arguments) {

	NTSTATUS Status;
	UCHAR* FunctionAddress;
	INT SystemCallIndex;

	UINT i;

	if (!inline_syscall::initialized) {
		inline_syscall::set_error(IS_INIT_NOT_APPLIED);
		return IS_INIT_NOT_APPLIED;
	}

	inline_syscall::callback();
	typedef returnType __stdcall NtFunction(args...);
	NtFunction* Function = (NtFunction*)inline_syscall::syscall_stub;

	for (i = 0; i < 2; i++) {
		std::string szname(ServiceName);
		std::ranges::transform(szname, szname.begin(), ::tolower);
		FunctionAddress = (UCHAR*)memory::get_proc_address((uintptr_t)hSubsystemInstances[i], fnv1a::rt(szname.c_str()));
		if (FunctionAddress != nullptr) {
			if (*(UINT*)FunctionAddress != 0xB8D18B4C) //mov r10, rcx \ mov eax, index
			{
				inline_syscall::set_error(IS_INTEGRITY_STUB_FAILURE);
				return IS_INTEGRITY_STUB_FAILURE;
			}

			SystemCallIndex = (UINT)FunctionAddress[4];
			memcpy(inline_syscall::get_stub() + 0x4, &SystemCallIndex, sizeof(UINT));
			if (i == 1) {
				memcpy(inline_syscall::get_stub(), FunctionAddress, 21);
			}


			inline_syscall::set_error(IS_SUCCESS);
			return Function(arguments...);
		}
	}

	inline_syscall::set_error(IS_MODULE_NOT_FOUND);
	return IS_MODULE_NOT_FOUND;
}

void Protection::Crash() {
	DYNAMIC_INSTRUCTION
	syscall(NtTerminateProcess, HANDLE(-1), -1);
}

void Protection::CheckIsDebugger() {
	DYNAMIC_INSTRUCTION
	ULONG Old{};
	try {
		static const uint8_t IsDbgPresent_shell[] = { 0xB8, 0x39, 0x05, 0x00, 0x00, 0xC3 };
		auto IsDbgPresent = PBYTE(imp("kernel32.dll", IsDebuggerPresent));
		if (IsDbgPresent) {
			memory::protect_mem(IsDbgPresent, 0x1000, PAGE_EXECUTE_READWRITE, Old);
			RtlCopyMemory(IsDbgPresent, IsDbgPresent_shell, sizeof(IsDbgPresent_shell));
			memory::protect_mem(IsDbgPresent, 0x1000, Old, Old);
			if (memcmp(IsDbgPresent, IsDbgPresent_shell, sizeof(IsDbgPresent_shell)) == 0) {
				isDebuggerPresentPatched.store(true);
			} else {
				Crash();
			}
		}

	} catch (std::exception& e) {

	}
}

void Protection::CheckDrivers() {
	DYNAMIC_INSTRUCTION
	static ULONG buflen = 0x10000;
	static std::unique_ptr<uint8_t[]> buffers(new uint8_t[buflen]);
	try {
		NTSTATUS Status = 0xC0000001;
		do {
			buffers.reset(new uint8_t[buflen]);
			Status = syscall(NtQuerySystemInformation, 0x0B, buffers.get(), buflen, &buflen);
		} while (!NT_SUCCESS(Status));
		const auto ModuleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffers.get());
		for (auto i = 0ul; i < ModuleInfo->NumberOfModules; i++) {
			const auto cur_module = &ModuleInfo->Modules[i];
			if (!cur_module || !cur_module->FullPathName || !*cur_module->FullPathName) {
				continue;
			}

			std::string driver_name(reinterpret_cast<const char*>(cur_module->FullPathName));
			std::transform(driver_name.begin(), driver_name.end(), driver_name.begin(), ::tolower);
			if (
				driver_name.find(xor_a("kprocesshacker")) != driver_name.npos ||
				driver_name.find(xor_a("procmon")) != driver_name.npos ||
				driver_name.find(xor_a("kdcom")) != driver_name.npos ||
				driver_name.find(xor_a("dbgv")) != driver_name.npos ||
				driver_name.find(xor_a("dbk64")) != driver_name.npos
			) {
				Crash();
			}
		}

	} catch (std::exception& e) {

	}
}

void Protection::AddMutex() {
	DYNAMIC_INSTRUCTION
	static bool bMutex = false;
	if (!bMutex) {
		bMutex = true;
		CreateMutexA(nullptr, TRUE, xor_a("$ IDA registry mutex $"));
		CreateMutexA(nullptr, TRUE, xor_a("$ IDA trusted_idbs"));
	}
}

void Protection::VmwareChecker() {
	DYNAMIC_INSTRUCTION
	std::vector<std::string> vm_modules;
	vm_modules.push_back(xor_a("vboxhook.dll"));
	vm_modules.push_back(xor_a("vmclientcore.dll"));
	vm_modules.push_back(xor_a("vmwarewui.dll"));
	vm_modules.push_back(xor_a("virtualbox.dll"));
	vm_modules.push_back(xor_a("vboxvmm.dll"));
	try {
		for (std::string szname : vm_modules) {
			const auto hModule = imp("kernel32.dll", LoadLibraryExA)(szname.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_SEARCH_SYSTEM32);
			if (hModule) {
				Crash();
			}
		}

	} catch (std::exception& e) {

	}
}

bool Protection::FindProcess(std::string szName) {
	DYNAMIC_INSTRUCTION
	PROCESSENTRY32W ProcessEntry = {};
	ProcessEntry.dwSize = sizeof(ProcessEntry);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!Process32First(hSnapShot, &ProcessEntry)) {
		return false;
	}

	do {
		std::wstring szProcess(szName.begin(), szName.end());
		if (wcsstr(ProcessEntry.szExeFile, szProcess.c_str())) {
			CloseHandle(hSnapShot);
			return true;
		}

	} while (Process32Next(hSnapShot, &ProcessEntry));
	CloseHandle(hSnapShot);
	return false;
}

NTSTATUS Protection::CreateThread(PHANDLE pOutThreadHandle, HANDLE hProcess, PVOID pStartAddress, PVOID pArgument) {
	DYNAMIC_INSTRUCTION
	return syscall(ZwCreateThreadEx, pOutThreadHandle, GENERIC_ALL, NULL, hProcess, reinterpret_cast<LPTHREAD_START_ROUTINE>(pStartAddress), pArgument, 0x40 | 0x00000004, 0, 0, 0, NULL);
}

void Protection::ProcessChecker() {
	DYNAMIC_INSTRUCTION
	static std::vector<std::string> vecBlackListPrograms = {
		xor_a("windbg.exe"), xor_a("x64dbg.exe"), xor_a("x32dbg.exe"), xor_a("ida.exe"),
		xor_a("ida64.exe"), xor_a("idaq.exe"), xor_a("idaq64.exe"), xor_a("procmon.exe"),
		xor_a("procmon64.exe"), xor_a("ollydbg.exe"), xor_a("scylla_x64.exe"), xor_a("scylla_x86.exe"), xor_a("unicorn")
	};

	try {
		for (std::string szName : vecBlackListPrograms) {
			if (FindProcess(szName)) {
				Crash();
			}
		}

	} catch (std::exception& e) {

	}
}

void Protection::Checker() {
	DYNAMIC_INSTRUCTION
	CompareHardwareFunction();
#ifndef __DEBUG
	try {
		std::lock_guard lock(Mutex);
		AddMutex();
		VmwareChecker();
		ProcessChecker();
		CheckDrivers();
	} catch (std::exception& e) {

	}
#endif
}

void Protection::CheckerThread() {
	while (true) {
		Checker();
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	};
}

void Protection::Setup() {
	Checker();
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	std::thread(CheckerThread).detach();
}