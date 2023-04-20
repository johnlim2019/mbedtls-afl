#!/bin/bash
date
pwd
echo "compiling for afl..."
if $HOME/AFL/afl-clang ./crypt_test_afl.c -o crypt_test_afl -lmbedcrypto -lmbedtls; then
    echo Try cbc
    if ./crypt_test_afl ./plaintext_seed/plain.txt ./options_seed/cbc.txt; then 
        echo CBC completed;
        echo try ctr;
        if ./crypt_test_afl ./plaintext_seed/plain.txt ./options_seed/ctr.txt; then 
            echo ctr completed;
            echo try ecb;
            if ./crypt_test_afl ./plaintext_seed/plain.txt ./options_seed/ecb.txt; then
                echo ecb completed;
                echo try cfb128;
                if ./crypt_test_afl ./plaintext_seed/plain.txt ./options_seed/cfb128.txt; then
                    echo cfb128 completed;
                    if ./crypt_test_afl ./aes_combined_seed/aes_combined_cbc.txt; then
                        echo combined cbc completed;
                        echo ALL TESTS PASSED;             
                        $HOME/AFL/afl-fuzz -m 1000 -i ./aes_combined_seed-afl/ -o ./results_aes -- ./crypt_test_afl @@               
                    fi
                fi
            fi
        fi
    else 
        echo non-fuzzing execution failed.
    fi
else    
    echo Compile Failed.
fi

