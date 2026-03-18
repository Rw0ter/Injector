#pragma once
#include <string>
#include <vector>
#include <Windows.h>

bool MapDriverFromMemory(const std::vector<uint8_t>& sysBuffer);
bool MapDriverFromFile(const std::wstring& sysPath);
