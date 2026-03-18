#pragma once
#include <atomic>

template <int... Pack> struct IndexList {};

template <typename IndexList, int Right> struct Append;

template <int... Left, int Right>
struct Append<IndexList<Left...>, Right> {
    using Result = IndexList<Left..., Right>;
};

template <int N>
struct ConstructIndexList {
    using Result = typename Append<typename ConstructIndexList<N - 1>::Result, N - 1>::Result;
};

template <>
struct ConstructIndexList<0> {
    using Result = IndexList<>;
};

#define XOR_SEED ( \
    (__TIME__[7] - '0') * 1  + (__TIME__[6] - '0') * 10  + \
    (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 + \
    (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000 \
)

template <int Line, int Counter>
struct XorBaseKey {
    static constexpr unsigned int value =
        static_cast<unsigned int>(XOR_SEED) ^
        (static_cast<unsigned int>(Line) * 2654435761u) ^
        (static_cast<unsigned int>(Counter) * 2246822519u);
};

template <int Line, int Counter>
struct XorKeyGeneratorA {
    static __forceinline constexpr unsigned char KeyByte(int index) {
        unsigned int k = XorBaseKey<Line, Counter>::value;
        k ^= 0xA3u * static_cast<unsigned int>(index + 1);
        k += 0x9E3779B9u * static_cast<unsigned int>(index * 3 + 7);
        k ^= (k >> ((index & 3) * 5));
        k += (k << ((index & 1) + 3));
        return static_cast<unsigned char>(k & 0xFFu);
    }
};

template <int Line, int Counter>
struct XorKeyGeneratorW {
    static __forceinline constexpr unsigned short KeyByte(int index) {
        unsigned int k = XorBaseKey<Line, Counter>::value;
        k ^= 0xB7u * static_cast<unsigned int>(index + 5);
        k += 0x85EBCA6Bu * static_cast<unsigned int>(index * 2 + 11);
        k ^= (k >> ((index & 2) * 3));
        k += (k << ((index & 1) + 4));
        return static_cast<unsigned short>(k & 0xFFFFu);
    }
};

template <int Line, int Counter>
__forceinline constexpr char EncryptCharacterA(const char ch, int index) {
    return static_cast<char>(ch ^ XorKeyGeneratorA<Line, Counter>::KeyByte(index));
}

template <int Line, int Counter>
__forceinline constexpr wchar_t EncryptCharacterW(const wchar_t ch, int index) {
    return static_cast<wchar_t>(ch ^ XorKeyGeneratorW<Line, Counter>::KeyByte(index));
}

template <int Line, int Counter, typename IndexList>
class XorA;

template <int Line, int Counter, int... Index>
class XorA<Line, Counter, IndexList<Index...>> {
private:
    char value_[sizeof...(Index) + 1];
    std::atomic<bool> decrypted_;
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;

public:
    __forceinline constexpr XorA(const char* const str)
        : value_{ EncryptCharacterA<Line, Counter>(str[Index], Index)... }, decrypted_(false) {
        value_[sizeof...(Index)] = '\0';
    }

    __declspec(noinline) __forceinline char* decrypt() {
        if (decrypted_.load(std::memory_order_acquire))
            return value_;

        while (lock_.test_and_set(std::memory_order_acquire)) { /* spin */ }

        if (!decrypted_.load(std::memory_order_relaxed)) {
            for (int i = 0; i < static_cast<int>(sizeof...(Index)); ++i) {
                value_[i] = static_cast<char>(
                    value_[i] ^ XorKeyGeneratorA<Line, Counter>::KeyByte(i)
                    );
            }
            decrypted_.store(true, std::memory_order_release);
        }

        lock_.clear(std::memory_order_release);
        return value_;
    }

    __forceinline char* get() {
        return decrypt();
    }
};

template <int Line, int Counter, typename IndexList>
class XorW;

template <int Line, int Counter, int... Index>
class XorW<Line, Counter, IndexList<Index...>> {
private:
    wchar_t value_[sizeof...(Index) + 1];
    std::atomic<bool> decrypted_;
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;

public:
    __forceinline constexpr XorW(const wchar_t* const str)
        : value_{ EncryptCharacterW<Line, Counter>(str[Index], Index)... }, decrypted_(false) {
        value_[sizeof...(Index)] = L'\0';
    }

    __declspec(noinline) __forceinline wchar_t* decrypt() {
        if (decrypted_.load(std::memory_order_acquire))
            return value_;

        while (lock_.test_and_set(std::memory_order_acquire)) { /* spin */ }

        if (!decrypted_.load(std::memory_order_relaxed)) {
            for (int i = 0; i < static_cast<int>(sizeof...(Index)); ++i) {
                value_[i] = static_cast<wchar_t>(
                    value_[i] ^ XorKeyGeneratorW<Line, Counter>::KeyByte(i)
                    );
            }
            decrypted_.store(true, std::memory_order_release);
        }

        lock_.clear(std::memory_order_release);
        return value_;
    }

    __forceinline wchar_t* get() {
        return decrypt();
    }
};

#define XOR_INTERNAL_LINE    (__LINE__)
#define XOR_INTERNAL_COUNTER (__COUNTER__)

#define xor_a(str) \
    ([]() -> char* { \
        using Indices = typename ConstructIndexList<sizeof(str) - 1>::Result; \
        static XorA<XOR_INTERNAL_LINE, XOR_INTERNAL_COUNTER, Indices> s_xor(str); \
        return s_xor.decrypt(); \
    }())

#define xor_w(str) \
    ([]() -> wchar_t* { \
        using Indices = typename ConstructIndexList<sizeof(str) / sizeof(wchar_t) - 1>::Result; \
        static XorW<XOR_INTERNAL_LINE, XOR_INTERNAL_COUNTER, Indices> s_xor(str); \
        return s_xor.decrypt(); \
    }())
