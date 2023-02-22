#!/bin/bash
date
pwd
echo "compiling for afl..."
if $HOME/AFL/afl-gcc -I../include ./crypt_test.c -o crypt_test ../library/*.c; then
    if  ./crypt_test ./plaintext_seed/plain.txt ./options.txt; then 
        $HOME/AFL/afl-fuzz -m 1000 -i ./plaintext_seed/  -o ./results_aes -- ./crypt_test @@ ./options.txt
    else 
        echo non-fuzzing execution failed.
    fi
else    
    echo Compile Failed.
fi
