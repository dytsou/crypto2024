#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "rsa.h"
#include <iostream>
#include <string>
#define ll unsigned long long
#define int unsigned long long

void encrypt();
void decrypt();
CryptoPP::Integer hex2int(std::string hex);
std::string ascii2hex(std::string ascii);
std::string int2hex(CryptoPP::Integer n);
std::string int2hex(CryptoPP::Integer n, int length);
std::string hex2ascii(std::string hex);

signed main(int argc, char *argv[]){
    using namespace CryptoPP;
    std::string mode;
    std::cin >> mode;
    if (mode == "enc")
        encrypt();
    else if (mode == "dec")
        decrypt();
    else
        std::cerr << "Invalid mode" << std::endl;
    return 0;
}

void encrypt(){
    using namespace CryptoPP;
    int length;
    std::string plain, hex_n, hex_e;
    std::cin >> length >> hex_n >> hex_e;
    std::getline(std::cin, plain);
    plain = plain.substr(1);
    CryptoPP::Integer n, e;
    n = hex2int(hex_n);
    e = hex2int(hex_e);
    Integer m((const byte *)plain.data(), plain.size());
    RSA::PublicKey pubKey;
    pubKey.Initialize(n, e);
    Integer c = pubKey.ApplyFunction(m);
    std::cout << int2hex(c, length) << std::endl;
}

void decrypt(){
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    int length;
    std::string hex_n, hex_d, cipher;
    std::cin >> length >> hex_n >> hex_d >> cipher;
    CryptoPP::Integer n, d, e, c, m;
    n = hex2int(hex_n);
    d = hex2int(hex_d);
    c = hex2int(cipher);
    RSA::PrivateKey priKey;
    for(int i = 1; i < (1<<31); i++){
        e = Integer(i);
        try{
            priKey.Initialize(n, e, d);
            break;
        }
        catch(const Exception& e){}
    }
    m = priKey.CalculateInverse(rng, c);
    std::cout << hex2ascii(int2hex(m)) << std::endl;
}

CryptoPP::Integer hex2int(std::string hex){
    CryptoPP::Integer result;
    for(int i = 0; i < hex.size(); i++){
        result = result * 16;
        if (hex[i] >= '0' && hex[i] <= '9')
            result += hex[i] - '0';
        else if (hex[i] >= 'a' && hex[i] <= 'f')
            result += hex[i] - 'a' + 10;
        else if (hex[i] >= 'A' && hex[i] <= 'F')
            result += hex[i] - 'A' + 10;
    }
    return result;
}

std::string ascii2hex(std::string ascii){
    std::string hex;
    for(int i = 0; i < ascii.size(); i++){
        hex += std::to_string((int)ascii[i]);
    }
    return hex;
}

std::string int2hex(CryptoPP::Integer n){
    std::string hex;
    while(n > 0){
        int r = n % 16;
        if (r < 10)
            hex = std::to_string(r) + hex;
        else
            hex = (char)('A' + r - 10) + hex;
        n /= 16;
    }
    return hex;
}

std::string int2hex(CryptoPP::Integer n, int length){
    std::string hex;
    while(n > 0){
        int r = n % 16;
        if (r < 10)
            hex = std::to_string(r) + hex;
        else
            hex = (char)('A' + r - 10) + hex;
        n /= 16;
    }
    if(hex.size() < length)
        hex = std::string(ceil(length/4) - hex.size(), '0') + hex;
    return hex;
}

std::string hex2ascii(std::string hex){
    std::string ascii;
    for(int i = 0; i < hex.size(); i += 2){
        int x = 0;
        if (hex[i] >= '0' && hex[i] <= '9')
            x += hex[i] - '0';
        else if (hex[i] >= 'a' && hex[i] <= 'f')
            x += hex[i] - 'a' + 10;
        else if (hex[i] >= 'A' && hex[i] <= 'F')
            x += hex[i] - 'A' + 10;
        x *= 16;
        if (hex[i+1] >= '0' && hex[i+1] <= '9')
            x += hex[i+1] - '0';
        else if (hex[i+1] >= 'a' && hex[i+1] <= 'f')
            x += hex[i+1] - 'a' + 10;
        else if (hex[i+1] >= 'A' && hex[i+1] <= 'F')
            x += hex[i+1] - 'A' + 10;
        ascii += (char)x;
    }
    return ascii;
}
