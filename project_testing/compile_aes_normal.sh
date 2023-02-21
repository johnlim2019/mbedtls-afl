#!/bin/bash
date
pwd
echo compiling...
gcc -I../include ./crypt_test.c -o crypt_test ../library/*.c
