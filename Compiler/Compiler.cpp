#include <fstream>
#include <filesystem>
#include <format>

#include "Compiler.hpp"
#include "../Aes/Aes.hpp"
#include "../Base64/Base64.h"


std::string CCompiler::Decompile(uint8_t* pData, const uint64_t nSize) {
	std::vector<uint8_t> vecData(nSize);
	std::memcpy(vecData.data(), pData, nSize);
	std::string szCompileStringData(vecData.begin(), vecData.end());
	return Decompile(szCompileStringData);
}

std::vector<uint8_t> CCompiler::DecompileToU8(uint8_t* pData, const uint64_t nSize) {
	std::string szData(reinterpret_cast<char*>(pData), nSize);
	std::vector<uint8_t> vecBytes(base64_decode2(szData));

	AES AesDecrypter(AESKeyLength::AES_192);
	std::string szEncryptKey(__ENCRYPT_KEY);
	std::vector<uint8_t> vecKey(szEncryptKey.begin(), szEncryptKey.end());
	AesDecrypter.PaddingData(vecBytes, 16);
	return AesDecrypter.DecryptECB(vecBytes, vecKey);
}

std::string CCompiler::Compile(std::vector<uint8_t> vecBytes) {
	AES AesDecrypter(AESKeyLength::AES_192);
	std::string szEncryptKey(__ENCRYPT_KEY);
	std::vector<uint8_t> vecKey(szEncryptKey.begin(), szEncryptKey.end());
	AesDecrypter.PaddingData(vecBytes, 16);
	std::vector<uint8_t> vecEncryptData = AesDecrypter.EncryptECB(vecBytes, vecKey);
	return base64_encode2(vecEncryptData);
}

std::string CCompiler::Compile(std::string szData) {
	std::vector<uint8_t> vecBytes(szData.begin(), szData.end());

	AES AesDecrypter(AESKeyLength::AES_192);
	std::string szEncryptKey(__ENCRYPT_KEY);
	std::vector<uint8_t> vecKey(szEncryptKey.begin(), szEncryptKey.end());
	AesDecrypter.PaddingData(vecBytes, 16);
	std::vector<uint8_t> vecEncryptData = AesDecrypter.EncryptECB(vecBytes, vecKey);
	return base64_encode2(vecEncryptData);
}

std::vector<uint8_t> CCompiler::CompileU8(std::vector<uint8_t> vecBytes) {
	AES AesDecrypter(AESKeyLength::AES_192);
	std::string szEncryptKey(__ENCRYPT_KEY);
	std::vector<uint8_t> vecKey(szEncryptKey.begin(), szEncryptKey.end());
	AesDecrypter.PaddingData(vecBytes, 16);
	std::vector<uint8_t> vecEncryptData = AesDecrypter.EncryptECB(vecBytes, vecKey);
	std::string szBase64 = base64_encode2(vecEncryptData);
	return std::vector<uint8_t>(szBase64.begin(), szBase64.end());
}

std::vector<uint8_t> CCompiler::DecompileU8(std::string szData) {
	std::vector<uint8_t> vecBytes(base64_decode2(szData));

	AES AesDecrypter(AESKeyLength::AES_192);
	std::string szEncryptKey(__ENCRYPT_KEY);
	std::vector<uint8_t> vecKey(szEncryptKey.begin(), szEncryptKey.end());
	AesDecrypter.PaddingData(vecBytes, 16);
	return AesDecrypter.DecryptECB(vecBytes, vecKey);
}

std::string CCompiler::Decompile(std::string szData) {
	std::vector<uint8_t> vecBytes(base64_decode2(szData));

	AES AesDecrypter(AESKeyLength::AES_192);
	std::string szEncryptKey(__ENCRYPT_KEY);
	std::vector<uint8_t> vecKey(szEncryptKey.begin(), szEncryptKey.end());
	AesDecrypter.PaddingData(vecBytes, 16);

	std::vector<uint8_t> vecDecryptAesData = AesDecrypter.DecryptECB(vecBytes, vecKey);
	std::string szDecryptData(vecDecryptAesData.begin(), vecDecryptAesData.end());
	return szDecryptData;
}

void CCompiler::BuildToLocalte(std::string szBuildLocalteFile, const bool bVerifyImage) {
	std::string szOutputFile(xor_a("CUserData.bin"));
	if (!std::filesystem::exists(szBuildLocalteFile)) {
		return;
	}

	std::ifstream pFile(szBuildLocalteFile, std::ios::in | std::ios::binary);
	if (!pFile.good() || !pFile.is_open()) {
		return;
	}

	pFile.seekg(0, std::ios::end);
	const uint64_t nDataSize = pFile.tellg();
	std::vector<uint8_t> vecBytes(nDataSize);
	pFile.seekg(0, std::ios::beg);
	pFile.read(reinterpret_cast<char*>(vecBytes.data()), vecBytes.size());

	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(vecBytes.data());
	while (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		vecBytes.clear();
		vecBytes.resize(nDataSize);
		pFile.read(reinterpret_cast<char*>(vecBytes.data()), vecBytes.size());
		pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(vecBytes.data());
	}

	std::string szCompileBase64Data = Compile(vecBytes);
	int nMagicNumber = *reinterpret_cast<uint16_t*>(szCompileBase64Data.data());
	while (nMagicNumber != 0x364C) {
		szCompileBase64Data = Compile(vecBytes);
		nMagicNumber = *reinterpret_cast<uint16_t*>(szCompileBase64Data.data());
		std::cout << std::format("Build Magic Number: {:02X}", nMagicNumber) << std::endl;
	}

	pFile.close();
	std::ofstream pOutFile(szOutputFile, std::ios::out | std::ios::binary);
	if (!pOutFile.good() || !pOutFile.is_open()) {
		return;
	}

	pOutFile.write(szCompileBase64Data.data(), szCompileBase64Data.size());
	pOutFile.close();
}