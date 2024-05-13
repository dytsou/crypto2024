#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "rsa.h"
#include "sha.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#define FILE "out.txt"

std::string msgs[11] = {
    "111550073",
    "00000000",
    "b4cc11f5",
    "e7b92b04",
    "847c7081",
    "a0e0e617",
    "535ea532",
    "b79cd8c1",
    "817968ac",
    "e55d2fa6",
    "28fc92f0"
};

struct Block {
    int num;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::byte nonce[4];
    void init() {
        for(int i = 0; i < 10; i++) {
            num = i;
            memset(digest, 0, CryptoPP::SHA256::DIGESTSIZE);
            memset(nonce, 0, 4);
        }
    }
    void store(int num, const CryptoPP::byte digest[], const CryptoPP::byte nonce[]) {
        this->num = num;
        memcpy(this->digest, digest, CryptoPP::SHA256::DIGESTSIZE);
        memcpy(this->nonce, nonce, 4);
    }
};

Block blocks[20];

void print(int num, const CryptoPP::byte digest[], const CryptoPP::byte nonce[]=nullptr) {
  printf("Block %d ", num);
  printf("Hash: ");
  for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; ++i) {
    printf("%02x", digest[i]);
  }
  printf(" Nonce: ");
  if (nonce == nullptr) {
    printf("%s\n", msgs[num+1].c_str());
    return;
  }
  for (int i = 0; i < 4; ++i) {
    printf("%02x", nonce[i]);
  }
  printf("\n");
}

void delete_lines(std::fstream &file, int num) {
    int lineToDelete = num * 4 - 3;
    printf("Regenerating block %d\n", num-1);
    std::string buffer[40];

    std::string line;
    int currentLine = 1;
    file.close();
    file.open(FILE, std::fstream::in);
    while (std::getline(file, line)) {
        // printf("Line %d: %s\n", currentLine, line.c_str());
        if (currentLine == lineToDelete) 
            break;
        buffer[currentLine++] = line;
    }
    file.close();
    std::fstream outFile(FILE, std::ios::out | std::ios::trunc);
    for (int i = 1; i < currentLine; ++i) {
        outFile << buffer[i] << "\n";
    }
    outFile.close();
    file.open(FILE, std::fstream::out | std::fstream::app);
}

int main() {
    blocks->init();
    CryptoPP::byte zero[CryptoPP::SHA256::DIGESTSIZE];
    memset(zero, 0, CryptoPP::SHA256::DIGESTSIZE);

    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::byte nonce[4];
    CryptoPP::byte preimage[CryptoPP::SHA256::DIGESTSIZE + 4];

    CryptoPP::HexEncoder hex_encoder;
    std::fstream file;
    file.open(FILE, std::fstream::out | std::fstream::trunc);
    hex_encoder.Attach(new CryptoPP::FileSink(file));
    CryptoPP::HexDecoder hex_decoder;
    std::string hex_string;


    std::string msg = msgs[0];
    hash.Update((const CryptoPP::byte *) msg.data(), msg.length());
    hash.Final(digest);

    file << 0 << "\n";
    hex_encoder.PutMessageEnd(digest, CryptoPP::SHA256::DIGESTSIZE);
    file << "\n";

    msg = msgs[1];
    hex_decoder.Attach(new CryptoPP::StringSink(hex_string));
    hex_decoder.PutMessageEnd((const CryptoPP::byte *) msg.data(), msg.length());
    memcpy(preimage, digest, CryptoPP::SHA256::DIGESTSIZE);
    memcpy(preimage + CryptoPP::SHA256::DIGESTSIZE, hex_string.data(), 4);
    hex_decoder.Detach();
    hex_string.clear();
    hash.Update(preimage, CryptoPP::SHA256::DIGESTSIZE + 4);
    hash.Final(digest);
    print(0, digest);

    file << msg << "\n";
    hex_encoder.PutMessageEnd(digest, CryptoPP::SHA256::DIGESTSIZE);
    file << "\n";

    for (uint8_t num = 1; num < 12; ++num) {
        file << +num << "\n";
        hex_encoder.PutMessageEnd(digest, CryptoPP::SHA256::DIGESTSIZE);
        file << "\n";
        long long count = 0;
        bool found = true;
        memcpy(preimage, digest, CryptoPP::SHA256::DIGESTSIZE);
        do {
            if (count++ > (1LL << 40) && num >= 10) {
                found = false;
                break;
            }
            else if (count++ > (1LL << 35) && num < 10) {
                found = false;
                break;
            }
            prng.GenerateBlock(nonce, 4);
            memcpy(preimage + CryptoPP::SHA256::DIGESTSIZE, nonce, 4);

            hash.Update(preimage, CryptoPP::SHA256::DIGESTSIZE + 4);
            hash.Final(digest);
        } while (memcmp(digest, zero, num >> 1) != 0 || ((num % 2) && ((digest[(num >> 1)] >> 4) ^ zero[num >> 1]) != 0));
        if (!found) {
            delete_lines(file, num);
            num -=2;
            memcpy(digest, blocks[num].digest, CryptoPP::SHA256::DIGESTSIZE);
            memcpy(nonce, blocks[num].nonce, 4);
            continue;
        }
        hex_encoder.PutMessageEnd(nonce, 4);
        file << "\n";
        hex_encoder.PutMessageEnd(digest, CryptoPP::SHA256::DIGESTSIZE);
        file << "\n";
        print(num, digest, nonce);
        blocks[num].store(num, digest, nonce);
    }

    hex_encoder.Detach();
    file.close();
    return 0;
}
