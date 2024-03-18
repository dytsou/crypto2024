#include<iostream>
#include<string>
#include<sstream>
#include<cmath>
using namespace std;

class DES{
    const int IP[64] = {    
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7 };
    const int IP_1[64] = {  
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25 };
    const int E[48] = {     
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1 };
    const int P[32] = {     
        16, 7,  20, 21, 
        29, 12, 28, 17,
        1,  15, 23, 26, 
        5,  18, 31, 10,
        2,  8,  24, 14, 
        32, 27, 3,  9,
        19, 13, 30, 6,  
        22, 11, 4,  25 };
    const int S[8][4][16] = {                        // S-box
        {
            { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
            { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
            { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
            { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
        },
        {
            { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
            { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
            { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
            { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
        },
        {
            { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
            { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
            { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
            { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
        },
        {
            { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
            { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
            { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
            { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
        },
        {
            { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
            { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
            { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
            { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
        },
        {
            { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
            { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
            { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
            { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
        },
        {
            { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
            { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
            { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
            { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
        },
        {
            { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
            { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
            { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
            { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
        }
    };
    const int PC_1[56] = {  
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4 };
    const int PC_2[48] = {  
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32 };
    const int shift[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
    void generate_keys();
    string key_64;
    string subkey[16];//48 bits
    string dec_to_bin(int n);
    string dec_to_4bit_bin(int n);
    string ascii_to_bin(const string &s);
    string bin_to_hex(const string &s);
    string shift_bit(const string &s, int n);
    string R_xor_key(const string &R, int round);
    string xor_bit(const string &a, const string &b);
    string get_s_box_element(const string &s, int n);
    
public:
    DES(): key(""), plaintext(""), key_64("") {}
    string key;
    string plaintext;
    string crypt();
};
            
signed main(){
    for(int i = 0; i < 5; i++){
        DES* des = new DES();
        cin >> des->key >> des->plaintext;
        cout << des->crypt() << endl;
        delete des;
    }
    return 0;
}

string DES::crypt(){
    string encrypted = "";
    generate_keys();
    //plaintext
    string plaintext_64 = ascii_to_bin(plaintext);
    string plaintext_64_IP = "";
    for(int i = 0; i < 64; i++) plaintext_64_IP += plaintext_64[IP[i] - 1];//64 bits plaintext after IP
    string L = plaintext_64_IP.substr(0, 32);
    string R = plaintext_64_IP.substr(32, 32);
    string L_temp;
    for(int i = 0; i < 16; i++){
        L_temp = L;
        L = R;
        R = xor_bit(L_temp, R_xor_key(R, i));
    }
    string temp = R + L;
    for(int i = 0; i < 64; i++)
        encrypted += temp[IP_1[i] - 1];
    return bin_to_hex(encrypted);
}

void DES::generate_keys(){
    key_64 = ascii_to_bin(key);
    string key_56 = "";//56 bits key after PC-1
    for(int i = 0; i < 56; i++) key_56 += key_64[PC_1[i] - 1];
    string key_left = key_56.substr(0, 28);//left 28 bits
    string key_right = key_56.substr(28, 28);//right 28 bits
    for(int j = 0; j < 16; j++){
        key_left = shift_bit(key_left, shift[j]);
        key_right = shift_bit(key_right, shift[j]);
        key_56 = key_left + key_right;
        subkey[j] = "";
        for(int i = 0; i < 48; i++)
            subkey[j] += key_56[PC_2[i] - 1];
    }
}

string DES::shift_bit(const string &s, int n){ // only in generate_keys
    return s.substr(n, s.size() - n) + s.substr(0, n);
}

string DES::ascii_to_bin(const string &s){
    string temp = "";
    for(char i : s){
        for(int j = 7; j >= 0; j--)
            temp += (i & (1 << j)) ? "1" : "0";
    }
    return temp;//64 bits
}

string DES::bin_to_hex(const string &s){
    string temp = "";
    for(int i = 0; i < s.size(); i+=4){
        string temp2 = s.substr(i, 4);
        if(temp2 == "0000") temp += "0";
        else if(temp2 == "0001") temp += "1";
        else if(temp2 == "0010") temp += "2";
        else if(temp2 == "0011") temp += "3";
        else if(temp2 == "0100") temp += "4";
        else if(temp2 == "0101") temp += "5";
        else if(temp2 == "0110") temp += "6";
        else if(temp2 == "0111") temp += "7";
        else if(temp2 == "1000") temp += "8";
        else if(temp2 == "1001") temp += "9";
        else if(temp2 == "1010") temp += "A";
        else if(temp2 == "1011") temp += "B";
        else if(temp2 == "1100") temp += "C";
        else if(temp2 == "1101") temp += "D";
        else if(temp2 == "1110") temp += "E";
        else if(temp2 == "1111") temp += "F";
    }
    return temp;
}

string DES::dec_to_bin(int n){
    string temp = "";
    for(int i = 0; i < 8; i++){
        if(n % 2 == 0) temp = "0" + temp;
        else temp = "1" + temp;
        n /= 2;
    }
    return temp;//8 bits
}
string DES::dec_to_4bit_bin(int n){
    string temp = "";
    for(int i = 0; i < 4; i++){
        if(n % 2 == 0) temp = "0" + temp;
        else temp = "1" + temp;
        n /= 2;
    }
    return temp;//4 bits
}

string DES::R_xor_key(const string &R, int round){
    string expanded = "";
    for(int i = 0; i < 48; i++)
        expanded += R[E[i] - 1];
    string xor_result = xor_bit(expanded, subkey[round]);
    string s_temp = "";
    for(int i = 0; i < 48; i+=6){
        string temp = xor_result.substr(i, 6);
        s_temp += get_s_box_element(temp, i / 6);
    }
    string p_32 = "";
    for(int i = 0; i < 32; i++)
        p_32 += s_temp[P[i] - 1];
    return p_32;
}

string DES::xor_bit(const string &a, const string &b){
    string temp = "";
    for(int i = 0; i < a.size(); i++){
        if(a[i] == b[i]) temp += "0";
        else temp += "1";
    }
    return temp;
}

string DES::get_s_box_element(const string &s, int n){
    int row = (s[0] - '0') * 2 + (s[5] - '0');
    int col = (s[1] - '0') * 8 + (s[2] - '0') * 4 + (s[3] - '0') * 2 + (s[4] - '0');
    return dec_to_4bit_bin(S[n][row][col]);
}

