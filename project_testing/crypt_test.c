#include "mbedtls/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

#define CIPHERTEXT_LEN 1024
#define MAX_LINE 1024
#define KEY_LEN 16
#define IV_LEN 16

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
int checkResult(unsigned char *decipher, unsigned char *text)
{
    if (memcmp(decipher, text, sizeof(decipher)) != 0)
    {
        printf("error\n");
        printf("Expected: %s\n", text);
        printf("Actual: %s\n", decipher);
        // assert(memcmp(decipher, text, sizeof(decipher)) == 0);
        exit(EXIT_FAILURE);
    }
}

static int aesCbc(unsigned char key[], unsigned char key2[], unsigned char iv[], unsigned char iv1[], unsigned char text[], int numBytes)
{
    printf("aes_cbc()\n");
    mbedtls_aes_context aes;
    mbedtls_aes_context aes2;
    mbedtls_aes_init(&aes);
    mbedtls_aes_init(&aes2);
    unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    int success = mbedtls_aes_setkey_enc(&aes, key, (unsigned int)(KEY_LEN * 8));
    if (success != 0)
    {
        printf("Failed to init key\n");
        exit(EXIT_FAILURE);
    }
    success = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, numBytes, iv, text, ciphered);
    if (success != 0)
    {
        printf("Failed to encrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Ciphertext: %s\n", ciphered);
    success = mbedtls_aes_setkey_dec(&aes2, key2, (unsigned int)(KEY_LEN * 8));
    if (success != 0)
    {
        printf("Failed to init dec key\n");
        exit(EXIT_FAILURE);
    }
    success = mbedtls_aes_crypt_cbc(&aes2, MBEDTLS_AES_DECRYPT, strlen((const char *)ciphered), iv1, ciphered, decipher);
    if (success != 0)
    {
        printf("Failed to decrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    mbedtls_aes_free(&aes2);
    checkResult(decipher, text);
    free(ciphered);
    free(decipher);
    printf("exiting aesCbc()\n\n");
    return EXIT_SUCCESS;
}
static int aesEcb(unsigned char key[], unsigned char key2[], unsigned char text[], int numBytes)
{
    printf("aes_ecb()\n");
    mbedtls_aes_context aes;
    mbedtls_aes_context aes2;
    mbedtls_aes_init(&aes);
    mbedtls_aes_init(&aes2);

    unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    int success = mbedtls_aes_setkey_enc(&aes, key, KEY_LEN * 8);
    if (success != 0)
    {
        printf("Failed to init key\n");
        exit(EXIT_FAILURE);
    }
    success = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, text, ciphered);
    if (success != 0)
    {
        printf("Failed to encrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_setkey_dec(&aes2, key2, KEY_LEN * 8);
    if (success != 0)
    {
        printf("Failed to init dec key\n");
        exit(EXIT_FAILURE);
    }
    success = mbedtls_aes_crypt_ecb(&aes2, MBEDTLS_AES_DECRYPT, ciphered, decipher);
    if (success != 0)
    {
        printf("Failed to decrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Deciphered: %s\n", decipher);
    char *texttest = sliceString((char *)text, 0, 16);
    mbedtls_aes_free(&aes);
    mbedtls_aes_free(&aes2);
    checkResult(decipher, texttest);
    free(ciphered);
    free(decipher);
    printf("exiting aesEcb()\n\n");
    return EXIT_SUCCESS;
}

static int aesCfb128(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{
    printf("aesCfb128()\n");
    unsigned char iv1[IV_LEN];
    copyArr(iv, iv1, IV_LEN);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    size_t *iv_off = calloc(1, sizeof(size_t));
    *iv_off = 0;

    int success = mbedtls_aes_setkey_enc(&aes, key, KEY_LEN * 8);
    if (success != 0)
    {
        printf("Failed to init key\n");
        exit(EXIT_FAILURE);
    }
    success = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, numBytes, iv_off, iv, (const char *)text, ciphered);
    if (success != 0)
    {
        printf("Failed to encrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Ciphertext: %s\n", ciphered);
    success = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, strlen((const char *)ciphered), iv_off, iv1, (const char *)ciphered, decipher);
    if (success != 0)
    {
        printf("Failed to dec\n");
        exit(EXIT_FAILURE);
    }
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    checkResult(decipher, text);
    free(iv_off);
    free(ciphered);
    free(decipher);
    printf("exiting aesCfb128()\n\n");
    return EXIT_SUCCESS;
}

static int aesCtr(unsigned char key[], unsigned char iv[], unsigned char text[], int numBytes)
{
    printf("aesCtr()\n");
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    unsigned char ciphered[CIPHERTEXT_LEN];
    unsigned char decipher[MAX_LINE];
    int success = mbedtls_aes_setkey_enc(&aes, key, KEY_LEN * 8);
    if (success != 0)
    {
        printf("Failed to init key\n");
        exit(EXIT_FAILURE);
    }
    unsigned char nonce_counter[16] = {0};
    unsigned char stream_block[16];
    unsigned char nonce_counter1[16] = {0};
    unsigned char stream_block1[16];
    size_t nc_off = 0;
    size_t nc_off1 = 0;
    success = mbedtls_aes_crypt_ctr(&aes, numBytes, &nc_off, nonce_counter, stream_block, text, ciphered);
    if (success != 0)
    {
        printf("Failed to encrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Ciphertext: %s\n", ciphered);
    success = mbedtls_aes_crypt_ctr(&aes, strlen((const char *)ciphered), &nc_off1, nonce_counter1, stream_block1, ciphered, decipher);
    if (success != 0)
    {
        printf("Failed to decrypt\n");
        exit(EXIT_FAILURE);
    }
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    checkResult(decipher, text);
    printf("exiting aesCtr()\n\n");
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    // *(int *)0xdeadbeef = 37;
    if (argc > 3 || argc == 1)
    {
        printf("Command argument syntax err.\n");
        printf("Eg: ./crypt_test ./plain.txt ./options.txt\n");
        printf("Eg: ./crypt_test ./plain + options.txt\n");
    }
    printf("\nStarted main function\n");
    // declare the variables
    long numBytes;
    unsigned char *text;
    unsigned char *cipher;
    unsigned char *key;
    unsigned char *key2;
    unsigned char *iv;
    unsigned char *iv2;

    if (argc == 3)
    {
        char *path = argv[1];
        FILE *file = fopen(path, "r");
        if (!file)
        {
            perror(path);
            exit(EXIT_FAILURE);
        }
        printf("Reading plain text file at %s\n", path);

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
            perror(optionsPath);
            exit(EXIT_FAILURE);
        }
        char *line_buf = NULL;
        int line_count = 0;
        size_t bufsize = 32;
        size_t characters;
        unsigned char *cipherArr[MAX_LINE];
        unsigned char *keyArr[MAX_LINE];
        unsigned char *keyArr2[MAX_LINE];
        unsigned char *ivArr[MAX_LINE];
        unsigned char *ivArr2[MAX_LINE];
        // get first three lines to get the three options, cipher, iv1, iv2
        characters = getline(&line_buf, &bufsize, optionsFile);
        strcpy((char *)cipherArr, line_buf);
        characters = getline(&line_buf, &bufsize, optionsFile);
        strcpy((char *)keyArr, line_buf);
        characters = getline(&line_buf, &bufsize, optionsFile);
        strcpy((char *)keyArr2, line_buf);
        characters = getline(&line_buf, &bufsize, optionsFile);
        strcpy((char *)ivArr, line_buf);
        characters = getline(&line_buf, &bufsize, optionsFile);
        strcpy((char *)ivArr2, line_buf);
        // trash
        free(line_buf);
        line_buf = NULL;

        // drop the line break and assign the values to the global variables.
        cipher = strtok((char *)cipherArr, "\n");
        key = strtok((char *)keyArr, "\n");
        key2 = strtok((char *)keyArr2, "\n");
        iv = strtok((char *)ivArr, "\n");
        iv2 = strtok((char *)ivArr2, "\n");
    }
    else if (argc == 2)
    {
        // only one file contain all values.
        // open combined file
        char *path = argv[1];
        FILE *file = fopen(path, "r");
        printf("Reading options file at %s\n", path);
        if (!file)
        {
            perror(path);
            return EXIT_FAILURE;
        }
        // get plaintext
        fseek(file, 0L, SEEK_END);
        numBytes = ftell(file);
        fseek(file, 0L, SEEK_SET);
        text = (char *)calloc(numBytes, sizeof(char));
        fread(text, sizeof(char), numBytes, file);
        fclose(file);
        // printf("%s\n",text);
        // printf("%d\n",(int)strlen(text));
        const char *needle = "\nendplain\n";
        char *pos = strstr(text, needle);
        if (pos == NULL)
        {
            printf("error in seed file\n");
            return 1;
        }
        *pos = '\0';
        printf("%s\n", text);

        // get ops
        char *optext = pos + strlen(needle);
        printf("%s\n", optext);
        // options
        cipher = strtok(optext, "\n");
        key = strtok(NULL, "\n");
        key2 = strtok(NULL, "\n");
        iv = strtok(NULL, "\n");
        iv2 = strtok(NULL, "\n");

        printf("exiting reading of file block\n");
    }
    numBytes = (int)strlen(text);
    printf("Plain: %s \nPlaintext size: %d\n", text, (int)numBytes);
    printf("Cipher: %s\n", cipher);
    printf("Key: %s\nKeysize: %d\n", key, (int)strlen(key));
    printf("IV: %s\nivSize: %d\n\n", iv, (int)strlen(iv));
    printf("IV2: %s\nivSize: %d\n\n", iv2, (int)strlen(iv));

    if (strcmp(cipher, "CBC") == 0)
    {
        aesCbc(key, key2, iv, iv2, text, numBytes);
    }
    else if (strcmp(cipher, "ECB") == 0)
    {
        aesEcb(key, key2, text, numBytes);
    }
    else if (strcmp(cipher, "CTR") == 0)
    {
        aesCtr(key, iv, text, numBytes);
    }
    else if (strcmp(cipher, "CFB128") == 0)
    {
        aesCfb128(key, iv, text, numBytes);
    }
    else // cipher was not recognised
    {
        printf("cipher code not recognised");
        // assert(1 == 0);
        return EXIT_FAILURE;
    }
    printf("exit successfully\n");
    return EXIT_SUCCESS;
}
