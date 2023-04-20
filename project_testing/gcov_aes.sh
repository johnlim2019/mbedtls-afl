#!/bin/bash
date
pwd
echo compiling...
gcc  --coverage crypt_test.c -o crypt_test -lmbedcrypto -lmbedtls
echo "---------------------"
echo "bug 11"
./crypt_test ./bugs/bug_11.txt
echo $?
echo
echo "---------------------"
echo "bug 14"
./crypt_test ./bugs/bug_14.txt
echo $?
echo
echo "---------------------"
echo "bug 15"
./crypt_test ./bugs/bug_15.txt
echo $?
echo
echo "---------------------"
echo "bug 16"
./crypt_test ./bugs/bug_16.txt
echo $?
echo
echo "---------------------"
echo "bug 17"
./crypt_test ./bugs/bug_17.txt
echo $?
echo
echo "---------------------"
echo "bug 18"
./crypt_test ./bugs/bug_18.txt
echo $?
# gcov crypt_test.c -m 
# cat crypt_test.c.gcov
# rm -rf crypt_test.gc*


echo "---------------------"
echo "bug 10"
./crypt_test ./bugs/bug_10.txt
echo $?