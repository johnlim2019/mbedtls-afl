#!/bin/bash
date
pwd
echo compiling...
gcc  --coverage crypt_test.c -o crypt_test -lmbedcrypto -lmbedtls
echo trying cfb
./crypt_test ./aes_combined_seed/aes_combined_cbc_plain_crlf.txt
gcov crypt_test.c -m 
echo cat
# cat crypt_test.c.gcov
# rm -rf crypt_test.gc*
