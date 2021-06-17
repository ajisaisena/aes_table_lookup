# AES Table lookup implementation
This is AES table lookup implementation which mainly refers to OpenSSL.

Please notice that we only implement single block 128-AES. This programs can run higher than 1.16Gb/s in my computer.
## Usage
``` shell
g++ aes.cpp -o aes
./aes
```