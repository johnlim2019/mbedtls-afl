#!/bin/bash
date
pwd
echo "compiling for afl..."
if $HOME/AFL/afl-gcc -I../include ./crypt_test.c -o crypt_test_afl ../library/*.c; then
    if  ./crypt_test_afl ./plaintext_seed/plain.txt ./options_seed/cbc.txt; then
        if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/cbc.txt; then 
            echo CBC completed;
            if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/ctr.txt; then 
                echo ctr completed;
                if ./crypt_test_normal ./plaintext_seed/plain.txt ./options_seed/ecb.txt; then
                    echo ecb completed;
                    echo ALL TESTS PASSED; 
                    $HOME/AFL/afl-fuzz -m 1000 -i ./plaintext_seed/ -o ./results_aes -- ./crypt_test_afl @@ ./options_seed/cbc.txt                
                fi
            fi
        fi
    else 
        echo non-fuzzing execution failed.
    fi
else    
    echo Compile Failed.
fi