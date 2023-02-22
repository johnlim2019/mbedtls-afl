#!/bin/bash
date
pwd
echo compiling...
if gcc -I../include ./crypt_test.c -o crypt_test_normal ../library/*.c; then
    ./crypt_test_normal ./plaintext_seed/plain.txt ./options.txt
else    
    echo Compile Failed.
fi