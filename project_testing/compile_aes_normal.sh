#!/bin/bash
date
pwd
echo compiling...
if gcc -I../include ./crypt_test.c -o crypt_test_normal ../library/*.c; then
    echo Try cbc
    if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/cbc.txt; then 
        echo CBC completed;
        echo try ctr;
        if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/ctr.txt; then 
            echo ctr completed;
            echo try ecb;
            if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/ecb.txt; then
                echo ecb completed;
                echo try cfb128;
                if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/cfb128.txt; then
                    echo cfb128 completed;
                    echo ALL TESTS PASSED;             
                fi
            fi
        fi
    fi
else    
    echo Compile Failed.
fi