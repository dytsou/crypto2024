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
CryptoPP::Integer hex2int(std::string hex);
std::string getLastBit(CryptoPP::Integer n);

signed main(int argc, char *argv[]){
    encrypt();
    return 0;
}

void encrypt(){
    using namespace CryptoPP;
    int length;
    std::string plain, hex_n, hex_e, hex_seed;
    std::cin >> length >> hex_n >> hex_e >> hex_seed;
    CryptoPP::Integer n, e, seed;
    n = hex2int(hex_n);
    e = hex2int(hex_e);
    seed = hex2int(hex_seed);
    std::string ans = "";
    RSA::PublicKey pubKey;
    pubKey.Initialize(n, e);
    for(int i=0; i<32; i++){
        seed = pubKey.ApplyFunction(seed);
        ans += getLastBit(seed);
    }
    std::cout << ans << std::endl;
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

std::string getLastBit(CryptoPP::Integer n){
    int r = n % 2;
    if(r) return "1";
    else return "0";
}



