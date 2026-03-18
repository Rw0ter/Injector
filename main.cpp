#include "includes.h"
#include <iostream>
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <random>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <fstream>
#include <filesystem>
#include "log.h"
#include <kdm_API.h>
#include "Image/DrvImage.h"
#include "utils/Dynamic Instruction.hpp"
#include "Compiler/Compiler.hpp"
#include "utils/Export Spoof.h"
#include "Protection/Protection.hpp"
#define MAKE_VECTOR_FROM_ARRAY(arr) std::vector<uint8_t>(arr, arr + sizeof(arr))

// #define __BUILD_COMPILE_TO_LOCAL

__forceinline std::string random_str() {
	std::random_device dev;
	std::mt19937 gen(dev());
	static std::string random = { };
	static std::string random_t = xor_a("123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
	int len = std::uniform_int_distribution(15, 30)(gen);
	for (int i = 0; i < len; ++i) {
		const int npos = std::uniform_int_distribution(0, static_cast<int>(random_t.size() - 1))(gen);
		random.push_back(random_t.at(npos));
	}

	return random;
}

auto main() -> int
{
#ifdef __BUILD_COMPILE_TO_LOCAL
		CCompiler::BuildToLocalte("fakepitch.dll");
	return 0;
#endif
	DYNAMIC_INSTRUCTION
		SPOOF_FUNC

	SPOOF_CALL(LI_FN(setlocale).forwarded_safe_cached())(LC_ALL, xor_a("chs"));
	std::string title = random_str();
	SPOOF_CALL(LI_FN(SetConsoleTitleA).forwarded_safe_cached())(title.c_str());

	Protection::Setup();


	auto buf = MAKE_VECTOR_FROM_ARRAY(DrvImage);
	if (!MapDriverFromMemory(buf)) {
		skar_text->skar_log(xor_a("Driver Map Failed"));
		SPOOF_CALL(LI_FN(system).forwarded_safe_cached())(xor_a("pause"));
		return -1;
	}

	Inject* inject = new Inject();
	skar_text->skar_debug(xor_a("Rw0ter Injector."));
	SPOOF_CALL(LI_FN(Sleep).forwarded_safe_cached())(5000);
	if (!inject->inject_module_from_memory_to_process_by_name(xor_w(L"cs2.exe"))) {
		SPOOF_CALL(LI_FN(system).forwarded_safe_cached())(xor_a("pause"));
	}
	
}