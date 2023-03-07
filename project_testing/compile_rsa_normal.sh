
if gcc  -I../include test_d.c -o test_d -L../library -lmbedtls -lmbedcrypto; then
    ./test_d ./plaintext_rsa/plain_rsa.txt
    else 
        echo failed to compile
    fi