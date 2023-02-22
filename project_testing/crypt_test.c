#define _POSIX_C_SOURCE 200112L

#include "mbedtls/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

#define CIPHER_LEN 5000
#define MAX_LINE 1024
#define KEY_LEN 16
#define IV_LEN 16

int copy_arr(unsigned char iv1[], unsigned char iv2[], int size)
{
    for (int i = 0; i < size; i++)
    {
        iv2[i] = iv1[i];
    }
    return 0;
}

static int aes_cbc(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{
    printf("Checking Input is multiple of 16\n");
    // assert(numBytes%16 ==0);
    if (numBytes % 16 != 0)
    {
        return EXIT_FAILURE;
    }
    unsigned char iv1[IV_LEN];
    copy_arr(iv, iv1, KEY_LEN);
    unsigned char ciphered[CIPHER_LEN];
    unsigned char decipher[MAX_LINE];
    mbedtls_aes_context aes;
    mbedtls_aes_context aes2;
    mbedtls_aes_setkey_enc(&aes, key, numBytes * 8);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, strlen((const char *)(text)), iv, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_setkey_dec(&aes2, key, numBytes * 8);
    mbedtls_aes_crypt_cbc(&aes2, MBEDTLS_AES_DECRYPT, strlen((const char *)(ciphered)), iv1, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    if (strcmp(decipher, text) != 0)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
static int aes_ecb(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{

}


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        ("Command argument syntax err.\n");
        ("Eg: ./crypt_test ./plain.txt ./options.txt\n");
    }
    printf("\nStarted main function\n");
    char *path = argv[1];
    FILE *file = fopen(path, "r");
    if (!file)
    {
        perror(path);
        return EXIT_FAILURE;
    }
    printf("Reading plain text file at %s\n", path);

    long numBytes;
    unsigned char *text;

    // we are taking the whole file as a single string input
    fseek(file, 0L, SEEK_END);
    numBytes = ftell(file);
    fseek(file, 0L, SEEK_SET);
    text = (char *)calloc(numBytes, sizeof(char));
    if (text == NULL)
    {
        return 1;
    }
    fread(text, sizeof(char), numBytes, file);
    fclose(file);

 
    // take in the options as tokens
    char *optionsPath = argv[2];
    FILE *optionsFile = fopen(optionsPath, "r");
    printf("Reading options file at %s\n", optionsPath);

    if (!optionsFile)
    {
        perror(path);
        return 1;
    }
    char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    char cipher[MAX_LINE];
    fgets(cipher, MAX_LINE, optionsFile);
    fgets(key, KEY_LEN, optionsFile);
    fgets(iv, KEY_LEN, optionsFile);
    fclose(optionsFile);

    printf("Plain: %s\n", text);
    printf("Key: %s\n", key);
    printf("Cipher: %s", cipher);

    if (strcmp(cipher, "CBC"))
    {
        if (aes_cbc(key, iv, text, numBytes) == EXIT_FAILURE)
            return EXIT_FAILURE;
    }
    if (strcmp(cipher, "ECB"))
    {

    }
    return EXIT_SUCCESS;
}
