#define _GNU_SOURCE

#include "mbedtls/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

#define CIPHERTEXT_LEN 10000
#define MAX_LINE 1024
#define KEY_LEN 1024
#define IV_LEN 1024
#define CIPHER_LEN 1024

char *sliceString(char *str, int start, int end)
{

    int i;
    int size = (end - start);
    char *output = (char *)malloc(size * sizeof(char));

    for (i = 0; start <= end; start++, i++)
    {
        output[i] = str[start];
    }

    output[size] = '\0';

    return output;
}

int copyArr(unsigned char iv1[], unsigned char iv2[], int size)
{
    for (int i = 0; i < size; i++)
    {
        iv2[i] = iv1[i];
    }
    return 0;
}

static int aesCbc(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{
    printf("aes_cbc()\n");
    printf("Checking Input is multiple of 16\n");
    // assert(numBytes%16 ==0);
    if (numBytes % 16 != 0)
    {
        printf("%d\n", numBytes);
        printf("bytesize is wrong\n");
        return EXIT_FAILURE;
    }
    unsigned char iv1[IV_LEN];
    copyArr(iv, iv1, KEY_LEN);
    mbedtls_aes_context aes;
    mbedtls_aes_context aes2;
    // printf("init");
    unsigned char ciphered[CIPHERTEXT_LEN];
    unsigned char decipher[MAX_LINE];
    // printf("init");
    mbedtls_aes_setkey_enc(&aes, key, numBytes * 8);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, strlen((const char *)(text)), iv, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_setkey_dec(&aes2, key, numBytes * 8);
    mbedtls_aes_crypt_cbc(&aes2, MBEDTLS_AES_DECRYPT, strlen((const char *)(ciphered)), iv1, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    mbedtls_aes_free(&aes2);

    if (strcmp(decipher, text) != 0)
    {
        perror("error");
        printf("Expected: %s", text);
        printf(" Actual: %s\n", decipher);
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}
static int aesEcb(unsigned char key[], unsigned char text[], int numBytes)
{
    printf("aes_ecb()\n");
    // printf("init");
    mbedtls_aes_context aes;
    mbedtls_aes_context aes2;
    mbedtls_aes_init(&aes);
    mbedtls_aes_init(&aes2);

    // printf("init");
    unsigned char ciphered[CIPHERTEXT_LEN];
    unsigned char decipher[MAX_LINE];
    // printf("init");
    mbedtls_aes_setkey_enc(&aes, key, numBytes * 8);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_setkey_dec(&aes2, key, numBytes * 8);
    mbedtls_aes_crypt_ecb(&aes2, MBEDTLS_AES_DECRYPT, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    char *texttest = sliceString((char *)text, 0, 16);
    mbedtls_aes_free(&aes);
    mbedtls_aes_free(&aes2);
    // printf("%s",texttest);
    if (strcmp(decipher, texttest) != 0)
    {
        perror("error");
        printf("Expected: %s", texttest);
        printf(" Actual: %s\n", decipher);
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}

static int aesCfb8(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{
    printf("aesCfb8()\n");
    unsigned char iv1[IV_LEN];
    copyArr(iv, iv1, KEY_LEN);
    mbedtls_aes_context aes;
    // printf("init");
    unsigned char ciphered[CIPHERTEXT_LEN];
    unsigned char decipher[MAX_LINE];
    // printf("init");
    mbedtls_aes_setkey_enc(&aes, key, numBytes * 8);
    mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_ENCRYPT, strlen((const char *)(text)), iv, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_DECRYPT, strlen((const char *)(ciphered)), iv1, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);

    if (strcmp(decipher, text) != 0)
    {
        perror("error");
        printf("Expected: %s", text);
        printf(" Actual: %s\n", decipher);
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}

static int aesOfb(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{
    unsigned char iv1[IV_LEN];
    copyArr(iv, iv1, KEY_LEN);
    mbedtls_aes_context aes;
    unsigned char ciphered[CIPHERTEXT_LEN];
    unsigned char decipher[MAX_LINE];
    mbedtls_aes_setkey_enc(&aes, key, numBytes * 8);
    mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_ENCRYPT, strlen((const char *)(text)), iv, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_crypt_cfb8(&aes, MBEDTLS_AES_DECRYPT, strlen((const char *)(ciphered)), iv1, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    if (strcmp(decipher, text) != 0)
    {
        perror("error");
        printf("Expected: %s", text);
        printf(" Actual: %s\n", decipher);
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
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
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }
    fread(text, sizeof(char), numBytes, file);
    fclose(file);

    // open options file
    char *optionsPath = argv[2];
    FILE *optionsFile = fopen(optionsPath, "r");
    printf("Reading options file at %s\n", optionsPath);
    if (!optionsFile)
    {
        perror(path);
        exit(EXIT_FAILURE);
    }
    char *line_buf = NULL;
    int line_count = 0;
    size_t bufsize = 32;
    size_t characters;
    // get first three lines to get the three options
    characters = getline(&line_buf, &bufsize, optionsFile);
    unsigned char *cipherArr[MAX_LINE];
    unsigned char *keyArr[MAX_LINE];
    unsigned char *ivArr[MAX_LINE];
    strcpy((char *)cipherArr, line_buf);
    characters = getline(&line_buf, &bufsize, optionsFile);
    strcpy((char *)keyArr, line_buf);
    characters = getline(&line_buf, &bufsize, optionsFile);
    strcpy((char *)ivArr, line_buf);
    // trash
    free(line_buf);
    line_buf = NULL;

    // drop the line break
    unsigned char *cipher = strtok((char *)cipherArr, "\n");
    unsigned char *key = strtok((char *)keyArr, "\n");
    unsigned char *iv = strtok((char *)ivArr, "\n");

    printf("Plain: %s\n", text);
    printf("Cipher: %s\n", cipher);
    printf("Key: %s\n", key);
    printf("IV: %s\n", iv);

    aesEcb(key, text, numBytes);
    aesCfb8(key, iv, text, numBytes);
    aesCbc(key, iv, text, numBytes);
    aesOfb(key, iv, text, numBytes);

    if (strcmp(cipher, "CBC") == 0)
    {
        aesCbc(key, iv, text, numBytes);
    }
    else if (strcmp(cipher, "ECB") == 0)
    {
        aesEcb(key, text, numBytes);
    }
    else if (strcmp(cipher, "CFB"))
    {
        aesCfb8(key, iv, text, numBytes);
    }
    else if (strcmp(cipher, "OFB"))
    {
        aesOfb(key, iv, text, numBytes);
    }
    else // cipher was not recognised
    {
        perror("cipher code not recognised");
        return EXIT_FAILURE;
    }
    printf("exit successfully\n");
    return EXIT_SUCCESS;
}
