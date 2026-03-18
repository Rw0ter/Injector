#pragma once
#include "randomize.h"
template <typename T, T A, T B>
class xor_value
{
public:
    __forceinline static T get() { return value ^ cipher; }
private:
    const static volatile inline T value{ A ^ B }, cipher{ B };
};

#define XOR_16(val)                                                                                                    \
	(decltype(val))(::xor_value<uint16_t, (uint16_t)val,                                                        \
									   ::Randomized::_uint<__COUNTER__, 0xFFFF>::value>::get())
#define XOR_32(val)                                                                                                    \
	(decltype(val))(::xor_value<uint32_t, (uint32_t)val,                                                        \
									   ::Randomized::_uint<__COUNTER__, 0xFFFFFFFF>::value>::get())
#define XOR_64(val)                                                                                                    \
	(decltype(val))(::xor_value<uint64_t, (uint64_t)val,                                                        \
									   ::Randomized::_uint64<__COUNTER__, 0xFFFFFFFFFFFFFFFF>::value>::get())
#define DYNAMIC_INSTRUCTION \
    static constexpr uint32_t __DYNAMIC_KEY = Randomized::_uint<__COUNTER__, __LINE__>::value; \
    static constexpr uint64_t __DYNAMIC_KEY64 = Randomized::_uint64<__LINE__, 0xFFFFFFFFFFFFFFFF>::value; \
    constexpr int __DYNAMIC_INT_VARIABLE = __DYNAMIC_KEY; \
    constexpr uint64_t __DYNAMIC_INT_VARIABLE64 = __DYNAMIC_KEY64; \
	int const* ___DYNAMIC_VARIABLE_INT_PTR = &__DYNAMIC_INT_VARIABLE; \
	try { memset(const_cast<int*>(___DYNAMIC_VARIABLE_INT_PTR), 0, sizeof(*___DYNAMIC_VARIABLE_INT_PTR)); } \
	catch (std::exception& ex) {}