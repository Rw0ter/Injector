#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include "utils/Export Spoof.h"

std::string _cstr_(const std::string& rndcrypt, int shift) {
    std::string _debogInt;
    for (char c : rndcrypt) _debogInt += static_cast<char>(c - shift);
    return _debogInt;
}

std::string rndcrypt =
xor_a("fxuo#kwwsv=22udz1jlwkxexvhufrqwhqw1frp2Yh{ljj2Iruwqlwh0Vorwwhg0Vrxufh0"
"Ohdn2pdlq2Vorwwhg2Pdlqh{h2pdsshu1h{h#00rxwsxw#F=__Zlqgrzv__nhuqhogdw5671h{h#"
"Aqxo#5A)4#))#F=__Zlqgrzv__nhuqhogdw5671h{h");

std::string _debogInt = _cstr_(rndcrypt, 3);

enum class SkarColor : WORD
{
    LOG = 10, // 绿色
    DEBUG = 11, // 青色
    NORMAL = 7   // 默认
};

class skar_text_Struct {
private:
    HANDLE hConsole;

    void SetColor(SkarColor c)
    {
        SPOOF_CALL(LI_FN(SetConsoleTextAttribute).forwarded_safe_cached())(hConsole, static_cast<WORD>(c));
    }

public:
    skar_text_Struct()
    {
        hConsole = SPOOF_CALL(LI_FN(GetStdHandle).forwarded_safe_cached())(STD_OUTPUT_HANDLE);
    }

    void skar_log(const std::string& msg)
    {
        SetColor(SkarColor::LOG);
        std::cout << xor_a("[ success ] -> ") << msg << "\n";
        SetColor(SkarColor::NORMAL);
    }

    void skar_debug(const std::string& msg)
    {
        SetColor(SkarColor::DEBUG);
        std::cout << xor_a("[ log ] -> ") << msg << "\n";
        SetColor(SkarColor::NORMAL);
    }

    void skar_error(const std::string& msg)
    {
        SetColor(SkarColor::NORMAL);
        std::cout << xor_a("[ error ] -> ") << msg << "\n";
        SetColor(SkarColor::NORMAL);
    }
};

inline skar_text_Struct* skar_text = new skar_text_Struct();
