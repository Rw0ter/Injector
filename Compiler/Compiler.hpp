#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "../ARC4/ARC4.h"
#include "../utils/xor.h"
#define __ENCRYPT_KEY "RWTDEVCRYPT0x07000D21"
class CCompiler {
public:
	static std::string Compile(std::string szData);
	static std::string Decompile(std::string szData);
	static std::string Compile(std::vector<uint8_t> vecBytes);
	static std::vector<uint8_t> DecompileU8(std::string szData);
	static std::string Decompile(uint8_t* pData, const uint64_t nSize);
	static std::vector<uint8_t> CompileU8(std::vector<uint8_t> vecBytes);
	static std::vector<uint8_t> DecompileToU8(uint8_t* pData, const uint64_t nSize);
	static void BuildToLocalte(std::string szBuildLocalteFile, const bool bVerifyImage = true);
};