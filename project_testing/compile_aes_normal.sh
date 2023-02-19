#!/bin/bash
date
pwd
gcc -I../include ./crypt_test.c -o .crypt_test ../library/*.c
./crypt_test ./plain.txt ./options.txt