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
    if (strcmp(decipher, text) != 0)
    {
        printf("error\n");
        printf("Expected: %s\n", text);
        printf("Actual: %s\n", decipher);
        assert(strcmp(decipher, text) == 0);
    }
}

static int aesCbc(unsigned char key[], unsigned char iv[], unsigned char iv1[], unsigned char text[], int numBytes)
{
    printf("aes_cbc()\n");
    // assert(numBytes%16 ==0);
    if (numBytes % 16 != 0)
    {
        printf("%d\n", numBytes);
        printf("bytesize is wrong\n");
        exit(EXIT_FAILURE);
    }
    printf("Input is multiple of 16\n");
    // unsigned char iv1[IV_LEN];
    // copyArr(iv, iv1, IV_LEN);
    mbedtls_aes_context aes;
    mbedtls_aes_context aes2;
    mbedtls_aes_init(&aes);
    mbedtls_aes_init(&aes2);
    // printf("init");
    unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    // printf("init");
    int success = mbedtls_aes_setkey_enc(&aes, key, (unsigned int)(KEY_LEN * 8));
    if (success != 0)
    {
        printf("Failed to init key\n");
        exit(EXIT_FAILURE);
    }
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, numBytes, iv, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_setkey_dec(&aes2, key, (unsigned int)(KEY_LEN * 8));
    mbedtls_aes_crypt_cbc(&aes2, MBEDTLS_AES_DECRYPT, strlen((const char *)ciphered), iv1, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    mbedtls_aes_free(&aes2);
    checkResult(decipher, text);
    free(ciphered);
    free(decipher);
    printf("exiting aesCbc()\n\n");
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
    unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    // printf("init");
    mbedtls_aes_setkey_enc(&aes, key, KEY_LEN * 8);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_setkey_dec(&aes2, key, KEY_LEN * 8);
    mbedtls_aes_crypt_ecb(&aes2, MBEDTLS_AES_DECRYPT, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    char *texttest = sliceString((char *)text, 0, 16);
    mbedtls_aes_free(&aes);
    mbedtls_aes_free(&aes2);
    // printf("%s",texttest);
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
    // printf("init");
    unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    // printf("init");
    size_t *iv_off = calloc(1, sizeof(size_t));
    *iv_off = 0;
    mbedtls_aes_setkey_enc(&aes, key, KEY_LEN * 8);
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, numBytes, iv_off, iv, (const char *)text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, strlen((const char *)ciphered), iv_off, iv1, (const char *)ciphered, decipher);
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
    // unsigned char *ciphered = calloc(1, (sizeof(unsigned char) * CIPHERTEXT_LEN));
    // unsigned char *decipher = calloc(1, (sizeof(unsigned char) * MAX_LINE));
    mbedtls_aes_setkey_enc(&aes, key, KEY_LEN * 8);
    unsigned char nonce_counter[16] = {0};
    unsigned char stream_block[16];
    unsigned char nonce_counter1[16] = {0};
    unsigned char stream_block1[16];
    size_t nc_off = 0;
    size_t nc_off1 = 0;
    mbedtls_aes_crypt_ctr(&aes, numBytes, &nc_off, nonce_counter, stream_block, text, ciphered);
    printf("Ciphertext: %s\n", ciphered);
    mbedtls_aes_crypt_ctr(&aes, strlen((const char *)ciphered), &nc_off1, nonce_counter1, stream_block1, ciphered, decipher);
    printf("Deciphered: %s\n", decipher);
    mbedtls_aes_free(&aes);
    checkResult(decipher, text);
    // free(ciphered);
    // free(decipher);
    printf("exiting aesCtr()\n\n");
    return EXIT_SUCCESS;
}

char *flip_bit_mutator(unsigned char *x)
{
    int length = strlen((const char *)x);
    char *xor = calloc(1,length);
    for (int i = 0; i < length; i++)
    {
        xor[i] = (char)(x[i] ^ 0xFF);
    }
    printf("%s\n", xor);
    return xor;
}

char *swap_mutator(unsigned char *x)
{
    int length = strlen((const char *)x);
    char *y = calloc(1,length);
    strcpy(y, (const char *)x);
    char z = 0;
    for (int i = 0; i < length; i++)
    {
        int j = rand() % length;
        z = y[i];
        y[i] = y[j];
        y[j] = z;
    }
    printf("%s", y);
    return y;
}

int main(int argc, char const *argv[])
{

    unsigned char *x = "hellowthere";
    printf("orginal str: %s\n", x);
    char *z = flip_bit_mutator(x);
    printf("bit flip mutator: %s\n", z);
    free(z);
    printf("orginal str: %s\n", x);
    char *y = swap_mutator(x);
    printf("swap mutator: %s\n", y);
    free(y);
    return 0;
}
