# crypt-aes

Implementation of the Advanced Encryption Standard (AES) cipher algorithm in GOLANG.

Created for educational purposes.

## Usage

### Creating a key
```
# Creates a 128-bit key
./crypt-aes --newkey -l 128
# Creates a 192-bit key (default)
./crypt-aes --newkey -l 192
# Creates a 256-bit key (default)
./crypt-aes --newkey -l 256
```
### Encrypting from standard input to standard output
```
cat originalfile | ./crypt-aes -e -k <key> > encryptedfile
```
If the key parameter is not informed, crypt-aes generates a random key and outputs it to standard error.
```
cat originalfile | ./crypt-aes -e > encryptedfile
Using key: 7db8c0f5ad323959f18d2f72024671a7ef3140bc266dedf6
```
### Decrypting from standard input to standard output
```
cat encryptedfile | ./crypt-aes -d -k <key>
```
### Encrypting from file
```
./crypt-aes -e -k <key> -i originalfile -o encryptedfile
```
### Decrypt from file
```
./crypt-aes -d -k <key> -i encryptedfile -o originalfile
```
### Usage description
```
./crypt-aes -h
```
