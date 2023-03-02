pwd
if $HOME/AFL/afl-clang -I../include ./test_d.c -o test_d_afl ../library/*.c; then
    # ./test_d_afl @@plaintext_seed/plain.txt
    $HOME/AFL/afl-fuzz -t 7000 -i./plaintext_rsa/ -o ./results_rsa -- ./test_d_afl @@              
    else 
        echo failed to compile
    fi
