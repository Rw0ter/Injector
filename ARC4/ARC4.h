/*
 * ARC4.h
 *
 *  Created on: Apr 6, 2016
 *      Author: fabio
 */
#ifndef ARC4_H_
#define ARC4_H_
#include <vector>
#include <string>
#include "..\Base64\Base64.h"
    /**
    * RC4 Encryptor utility for decrypting Strings
    * @brief Utility to RC4 encrypt bytes
    */
    class ARC4{
        public:
            /**
            * Set/Reset the key use this method if you want to reuse the same ARC4 structure again
            * @param k the key
            * @param size the size of the key
            */
            void setKey(unsigned char * k,int size);
            /**
            * Encrypts a string
            * @param in String to encrypt 
            * @param out String to decrypt
            * @param size size of the key to encrypt
            */
            void encrypt(unsigned char * in,unsigned char * out,int size);
            /**
            * Encrypts a string
            * @param in String to encrypt 
            * @param out String to decrypt
            * @param size size of the key to encrypt
            */
            void encrypt(char * in,char * out,int size);
            ARC4();
        protected:
            void ksa(unsigned char * key);
            void swap(unsigned char data[],int i ,int j);
            void prga(unsigned char * plaintext,unsigned char * cipher,int size);
            void prga(char * plaintext,char * cipher,int size);
            unsigned char sbox[256];
            int sizeKey,prgaIndexA,prgaIndexB;
    };

    using namespace std;
    static std::string ReplaceString(std::string& src, std::string target, std::string replacement) {
        std::string result = src;
        size_t pos = 0;
        while ((pos = result.find(target, pos)) != std::string::npos) {
            result.replace(pos, target.length(), replacement);
            pos += replacement.length();
        }
        return result;
    }

    static std::string base64_encode2(const vector<unsigned char>& data) {
        const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        std::string encoded;
        int i = 0;
        unsigned char char_array_3[3], char_array_4[4];

        for (auto& byte : data) {
            char_array_3[i++] = byte;
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                    encoded += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        // 处理剩余字节
        if (i) {
            for (int j = i; j < 3; j++)
                char_array_3[j] = 0x00;

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (int j = 0; j < i + 1; j++)
                encoded += base64_chars[char_array_4[j]];

            while (i++ < 3)
                encoded += '=';
        }

        return encoded;
    }

    static vector<unsigned char> base64_decode2(const std::string& encoded_string) {
        const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        vector<unsigned char> ret;
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];

        size_t in_len = encoded_string.size();
        while (in_len-- && (encoded_string[in_] != '=')) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3C) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++)
                    ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (j = 0; j < 4; j++)
                char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3C) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; j < i - 1; j++)
                ret.push_back(char_array_3[j]);
        }

        return ret;
    }

    static string decrypt_rc4(const string& pwd, const string& enc_data) {
        int key[256];
        int box[256];
        size_t pwd_len = pwd.size();

        // 初始化密钥和置换盒
        for (int i = 0; i < 256; ++i) {
            if (pwd_len == 0) {
                key[i] = 0;
            }
            else {
                unsigned char c = static_cast<unsigned char>(pwd[i % pwd_len]);
                key[i] = (static_cast<int>(c) << 8) | c;
            }
            box[i] = i;
        }

        // 置换盒置换
        for (int i = 0, j = 0; i < 256; ++i) {
            j = (j + box[i] + key[i]) % 256;
            swap(box[i], box[j]);
        }

        // Base64解码
        vector<unsigned char> cipherBytes = base64_decode2(enc_data);
        vector<unsigned char> dataBytes(cipherBytes.size());

        // RC4解密过程
        int a = 0, j_val = 0;
        for (size_t i = 0; i < cipherBytes.size(); ++i) {
            a = (a + 1) % 256;
            j_val = (j_val + box[a]) % 256;
            swap(box[a], box[j_val]);
            int k = box[(box[a] + box[j_val]) % 256];
            dataBytes[i] = static_cast<uint8_t>(cipherBytes[i]) ^ static_cast<unsigned char>(k);
        }

        // 转换为字符串
        return string(dataBytes.begin(), dataBytes.end());
    }

    static string encrypt_rc4(const string& pwd, const string& data) {
        int key[256];
        int box[256];
        size_t pwd_len = pwd.size();

        // 密钥初始化（双字节重复模式）
        for (int i = 0; i < 256; ++i) {
            if (pwd_len == 0) {
                key[i] = 0;
            }
            else {
                unsigned char c = static_cast<unsigned char>(pwd[i % pwd_len]);
                key[i] = (static_cast<int>(c) << 8) | c;
            }
            box[i] = i;
        }

        // 置换盒初始化
        for (int i = 0, j = 0; i < 256; ++i) {
            j = (j + box[i] + key[i]) % 256;
            swap(box[i], box[j]);
        }

        // 转换明文为字节数组
        vector<unsigned char> dataBytes(data.begin(), data.end());
        vector<unsigned char> cipherBytes(dataBytes.size());

        // RC4加密核心
        int a = 0, j_val = 0;
        for (size_t i = 0; i < dataBytes.size(); ++i) {
            a = (a + 1) % 256;
            j_val = (j_val + box[a]) % 256;
            swap(box[a], box[j_val]);
            int k = box[(box[a] + box[j_val]) % 256];
            cipherBytes[i] = dataBytes[i] ^ static_cast<unsigned char>(k);
        }

        // Base64编码结果
        return base64_encode2(cipherBytes);
    }


#endif /* ARC4_H_ */
