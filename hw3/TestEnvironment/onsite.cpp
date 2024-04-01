#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "filters.h"
#include "aes.h"

#include <iostream>
#include <string>
#include <cstring>
using namespace CryptoPP;

void ECB_encrypt(std::string plain, std::string keyStr);
void CBC_encrypt(std::string plain, std::string keyStr, std::string ivStr);
void CFB_encrypt(std::string plain, std::string keyStr, std::string ivStr, int feedback);
std::string int_to_hex(int x);
std::string padding(int x);
bool ECB_decrypt(std::string ciphertext, std::string keyStr);
bool CBC_decrypt(std::string plain, std::string keyStr, std::string ivStr);
bool CFB_decrypt(std::string plain, std::string keyStr, std::string ivStr, int feedback);

int main(int argc, char* argv[])
{
    std::string ciphertext, keyStr, iv;
    iv = "0000000000000000";
    getline(std::cin, ciphertext);
    for(int i=0; i<(1<<16); i++){
        keyStr = padding(i);
        if(CFB_decrypt(ciphertext, keyStr, iv, 2)) return 0;
        if(CFB_decrypt(ciphertext, keyStr, iv, 4)) return 0;
        if(CFB_decrypt(ciphertext, keyStr, iv, 8)) return 0;
    }
    return 1;
}

void ECB_encrypt(std::string plain, std::string keyStr){
    std::string cipher = "";
    HexEncoder encoder(new FileSink(std::cout));
    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    try
    {
        ECB_Mode< AES >::Encryption e;
        e.SetKey(key, key.size());
        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher),
                StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    // std::cout << "cipher text(ECB): ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;
}

void CBC_encrypt(std::string plain, std::string keyStr, std::string ivStr){
    std::string cipher = "";
    HexEncoder encoder(new FileSink(std::cout));
    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    SecByteBlock iv((const byte*)ivStr.data(), ivStr.size());
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher),
                StreamTransformationFilter::ONE_AND_ZEROS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    // std::cout << "cipher text(CBC): ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;
}

void CFB_encrypt(std::string plain, std::string keyStr, std::string ivStr, int feedback){
    std::string cipher = "";
    HexEncoder encoder(new FileSink(std::cout));
    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    SecByteBlock iv((const byte*)ivStr.data(), ivStr.size());
    try
    {
        SecByteBlock iv((const byte*)ivStr.data(), ivStr.size());
        CFB_Mode< AES >::Encryption e(key, key.size(), iv, feedback);

        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    // std::cout << "cipher text(CFB): ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;
}

std::string int_to_hex(int x){
    std::string result = "";
    for(int i=0; i<4; i++){
        int r = x%16;
        char bit;
        if(r<10) bit = '0'+ r;
        else if(r<16) bit = 'A' + r - 10;
        result = bit + result;
        x/=16;
    }
    return result;
}

std::string padding(int x){
    std::string keyStr = "Our key is: ";
    keyStr += int_to_hex(x);
    return keyStr;
}

bool ECB_decrypt(std::string ciphertext, std::string keyStr){
    std::string cipher;
    StringSource ss(ciphertext, true, new HexDecoder(new StringSink(cipher)));
    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    std::string recovered = "";
    try
    {
        ECB_Mode< AES >::Decryption d;
        d.SetKey(key, key.size());
        StringSource ss(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered),
                StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
        for(int i = 0; i < recovered.size(); i++){
            if(recovered[i] < 32 || recovered[i] > 126 ){
                throw Exception(Exception::OTHER_ERROR, "Invalid key");
            }
        }
        std::cout << keyStr << std::endl;
        std::cout << recovered << std::endl;
        return true;
    }
    catch(const Exception& e){
        return false;
    }
}

bool CBC_decrypt(std::string ciphertext, std::string keyStr, std::string ivStr){
    std::string cipher;
    StringSource ss(ciphertext, true, new HexDecoder(new StringSink(cipher)));
    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    SecByteBlock iv((const byte*)ivStr.data(), ivStr.size());
    std::string recovered = "";
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered),
                StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
        for(int i = 0; i < recovered.size(); i++){
            if(recovered[i] < 32 || recovered[i] > 126 ){
                throw Exception(Exception::OTHER_ERROR, "Invalid key");
            }
        }
        std::cout << keyStr << std::endl;
        std::cout << recovered << std::endl;
        return true;
    }
    catch(const Exception& e){
        return false;
    }
}

bool CFB_decrypt(std::string ciphertext, std::string keyStr, std::string ivStr, int feedback){
    std::string cipher;
    StringSource ss(ciphertext, true, new HexDecoder(new StringSink(cipher)));
    SecByteBlock key((const byte*)keyStr.data(), keyStr.size());
    SecByteBlock iv((const byte*)ivStr.data(), ivStr.size());
    std::string recovered = "";
    try
    {
        CFB_Mode< AES >::Decryption d(key, key.size(), iv, feedback);
        StringSource ss(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource
        for(int i = 0; i < recovered.size(); i++){
            if(recovered[i] < 32 || recovered[i] > 126 ){
                throw Exception(Exception::OTHER_ERROR, "Invalid key");
            }
        }
        std::cout << recovered << std::endl;
        return true;
    }
    catch(const Exception& e){
        return false;
    }
}