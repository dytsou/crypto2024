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
std::string padding(int x);
void ECB_decrypt(std::string ciphertext, std::string keyStr);
void CBC_decrypt(std::string plain, std::string keyStr, std::string ivStr);
void CFB_decrypt(std::string plain, std::string keyStr, std::string ivStr, int feedback);

int main(int argc, char* argv[])
{   
    /*
    // AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));
    
    // SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    // SecByteBlock iv(AES::BLOCKSIZE);

    // prng.GenerateBlock(key, key.size());
    // prng.GenerateBlock(iv, iv.size());

    // const byte keyData[] = {};
    // const byte ivData[] = {};

    // memcpy(key, keyData, sizeof(keyData));
    // memcpy(iv, ivData, sizeof(ivData));
    */
    // I
    std::string plain = "AES is the US block cipher standard.";
    std::string keyStr = "2357111317192329";
    // ECB Mode
    ECB_encrypt(plain, keyStr);
    // CBC Mode
    CBC_encrypt(plain, keyStr, "1234567812345678");
    // CFB Mode
    CFB_encrypt(plain, keyStr, "9999999999999999", 2);
    // II
    std::string ciphertext;
    ciphertext = "104839DE2B34D9BA96F6E054F79F865890B827381D22FC3388690794F0D08EB3";
    for(int i=0; i<100000; i++)
        ECB_decrypt(ciphertext, padding(i));
    // I of III
    getline(std::cin, plain);
    // ECB Mode
    ECB_encrypt(plain, keyStr);
    // CBC Mode
    CBC_encrypt(plain, keyStr, "1234567812345678");
    // CFB Mode
    CFB_encrypt(plain, keyStr, "9999999999999999", 2);
    // II of III
    getline(std::cin, ciphertext);
    for(int i=0; i<100000; i++)
        ECB_decrypt(ciphertext, padding(i));
    return 0;
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
                new StringSink(cipher)
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

std::string padding(int x){
    std::string keyStr = "";
    if(x < 10){
        keyStr = "000000000000000" + std::to_string(x);
    }else if(x >= 10 && x < 100 ){
        keyStr = "00000000000000" + std::to_string(x);
    }else if(x >= 100 && x < 1000){
        keyStr = "0000000000000" + std::to_string(x);
    }else if(x >= 1000 && x < 10000){
        keyStr = "000000000000" + std::to_string(x);
    }else if(x >= 10000 && x < 100000){
        keyStr = "00000000000" + std::to_string(x);
    }
    return keyStr;
}

void ECB_decrypt(std::string ciphertext, std::string keyStr){
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
    }
    catch(const Exception& e){}
}

void CBC_decrypt(std::string ciphertext, std::string keyStr, std::string ivStr){
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
    }
    catch(const Exception& e){}
}

void CFB_decrypt(std::string ciphertext, std::string keyStr, std::string ivStr, int feedback){
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
    }
    catch(const Exception& e){}
}