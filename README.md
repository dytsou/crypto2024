## HW2 DES implementation

Homework: Read 5 inputs from stdin and writ 5 outputs to stdout. 

Onsite test: Modify DES and read 2 inputs from stdin and write 2 outputs to stdout

## HW3 AES using Crypto++ library

Homework: 

I. Use the template plaintext and key to encrypt the plaintext using AES in ECB mode with `PKCS_PADDING`, CBC mode with `ONE_AND_ZEROS_PADDING`, and CFB mode with `feedback size = 2`.

II. Use the template ciphertext to decrypt the ciphertext using AES in ECB mode with `PKCS_PADDING`. We have to find the key which is a 16-byte string between `0000000000000000` and `0000000000099999`.

III. Do the same as I and II but with stdin plaintext in I and stdin ciphertext in II.

Onsite test: Decrypt the ciphertext using AES in CFB with `feedback size = 2, 4, or 8` and key is of form `Our key is: XXXX` where `XXXX` is a 4 HEX digit string.
## HW4 RSA using Crypto++ library

Homework: Do either encryption or decryption using RSA, where the input format is `enc` `n` `e` `m` for encryption and `dec` `n` `d` `c` for decryption. We have to find the public key `e` for decryption.