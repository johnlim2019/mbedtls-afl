
#define _POSIX_C_SOURCE 200112L

#include "mbedtls/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_LINE 100

// char trim(char *str)
// {
//   char *end;

//   // Trim leading space
//   while (isspace((unsigned char)*str))
//     str++;

//   if (*str == 0) // All spaces?
//     return str;

//   // Trim trailing space
//   end = str + strlen(str) - 1;
//   while (end > str && isspace((unsigned char)*end))
//     end--;

//   // Write new null terminator character
//   // end[1] = '\0';

//   return str;
// }

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
  printf("Reading file at %s\n", path);

  long numBytes;
  char *text;

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

  printf("Plain: %s\n", text);

  // take in the options as tokens
  char *optionsPath = argv[2];
  FILE *optionsFile = fopen(optionsPath, "r");
  printf("Reading file at %s\n", optionsPath);

  if (!optionsFile)
  {
    perror(path);
    return 1;
  }
  char cipher[MAX_LINE];
  char key[MAX_LINE];
  fgets(cipher, MAX_LINE, optionsFile);
  fgets(key, MAX_LINE, optionsFile);
  fclose(optionsFile);

  printf("key: %s ", key);
  printf("cipher: %s\n", cipher);

  char ciphered[numBytes];
  char decipher[numBytes];
  // mbedtls_aes_context aes;
  // mbedtls_aes_setkey_enc(&aes, key, 256);
  // unsigned char iv[16];
  // mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 48, iv, text, output );
  // printf("%s\n",output);
  // mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, 48, iv, output, decipher);
  // printf("%s\n",decipher);
}
