#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
#include <string.h>
#include <assert.h>
#define EXPONENT 65537


#define KEY_SIZE 2048

void gen_key();

int main(int argc, char **argv) {


    FILE *f_input;
    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    const char *pers = "rsa_test";

    FILE *f_d;
    int ret_d = 1;
    unsigned c;
    size_t i_d;
    mbedtls_rsa_context rsa_d;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy_d;
    mbedtls_ctr_drbg_context ctr_drbg_d;
    unsigned char result[1024];
    unsigned char buf_d[512];
    const char *pers_d = "rsa_decrypt";


    // Initialize the RSA context
     mbedtls_printf("\n  . Seeding the random number generator...\n");
    fflush(stdout);

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&rsa);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *) pers,
                                strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
        goto exit;
    }

    if (argc != 2) {
        mbedtls_printf("usage: rsa_encrypt <input file>\n");

#if defined(_WIN32)
        mbedtls_printf("\n");
#endif

        mbedtls_exit(exit_code);
    }

    gen_key();

    // read public key 
    if ((f = fopen("rsa_pub.txt", "rb")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not open rsa_pub.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
        goto exit;
    }

    if ((ret = mbedtls_mpi_read_file(&N, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&E, 16, f)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                       ret);
        fclose(f);
        goto exit;
    }
    fclose(f);

    if ((ret = mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_import returned %d\n\n",
                       ret);
        goto exit;
    }
//read file  input 
    if ((f_input = fopen(argv[1], "r")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not open %s\n\n", argv[1]);
        goto exit;
    }



    fseek(f_input, 0, SEEK_END);
    size_t input_len = ftell(f_input);

    fseek(f_input, 0, SEEK_SET);




    // Allocate memory for the file content
     char *content = malloc(input_len + 1);
    if (content == NULL) {
        printf("Error: could not allocate memory\n");
        fclose(f);
        return 1;
    }

     if (input_len > 1024) {
        mbedtls_printf(" Input data larger than 1024 characters.\n\n");
        fclose(f_input);
        goto exit;
    }

    // Read the file content into the buffer
    fread(content, input_len, 1, f_input);
    fclose(f_input);

    // Add a null terminator to the end of the buffer
    // content[input_len] = '\0';

    // Print the content of the file
    printf("%s\n", content);
    memcpy(input, content, 1024);


   

    // memcpy(input, argv[1], strlen(argv[1]));

     mbedtls_printf("\n  . Generating the RSA encrypted value");
    fflush(stdout);

    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random,
                                    &ctr_drbg, strlen(content), input, buf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
                       ret);
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    if ((f = fopen("result-enc.txt", "wb+")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not create %s\n\n", "result-enc.txt");
        goto exit;
    }

    for (i = 0; i < rsa.MBEDTLS_PRIVATE(len); i++) {
        mbedtls_fprintf(f, "%02X%s", buf[i],
                        (i + 1) % 16 == 0 ? "\r\n" : " ");
    }

    fclose(f);

    mbedtls_printf("\n  . Done (created \"%s\")\n\n", "result-enc.txt");

    exit_code = MBEDTLS_EXIT_SUCCESS;

    ret =1;


    memset(result, 0, sizeof(result));


    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_rsa_init(&rsa);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *) pers_d,
                                strlen(pers_d));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
        goto exit_d;
    }

    mbedtls_printf("\n  . Reading private key from rsa_priv.txt");
    fflush(stdout);

    if ((f = fopen("rsa_priv.txt", "rb")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not open rsa_priv.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
        goto exit_d;
    }

    if ((ret = mbedtls_mpi_read_file(&N, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&E, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&D, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&P, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&Q, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&DP, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&DQ, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&QP, 16, f)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                       ret);
        fclose(f);
        goto exit_d;
    }
    fclose(f);

    if ((ret = mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_import returned %d\n\n",
                       ret);
        goto exit_d;

     }

    if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                       ret);
        goto exit_d;
    }

    /*
     * Extract the RSA encrypted value from the text file
     */
    if ((f = fopen("result-enc.txt", "rb")) == NULL) {
        mbedtls_printf("\n  ! Could not open %s\n\n", "result-enc.txt");
        goto exit_d;
    }

    i = 0;

    while (fscanf(f, "%02X", (unsigned int *) &c) > 0 &&
           i < (int) sizeof(buf_d)) {
        buf_d[i++] = (unsigned char) c;
    }

    fclose(f);

    if (i != rsa.MBEDTLS_PRIVATE(len)) {
        mbedtls_printf("\n  ! Invalid RSA signature format\n\n");
        goto exit_d;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf("\n  . Decrypting the encrypted data");
    fflush(stdout);

    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random,
                                    &ctr_drbg, &i,
                                    buf_d, result, 1024);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                       ret);
        goto exit_d;
    }

    mbedtls_printf("\n  . OK\n\n");

    mbedtls_printf("The decrypted result is: '%s'\n\n", result);

    exit_code = MBEDTLS_EXIT_SUCCESS;



    int comparison_result = strcmp(result, input);

if (comparison_result == 0) {
            printf("Success\n");
        printf("Expected: %s\n", input);
        printf("Actual: %s\n", result);
                    exit(EXIT_SUCCESS);


} else 
{
       printf("error\n");
        printf("Expected: %s\n", input);
        printf("Actual: %s\n", result);
        exit(EXIT_FAILURE);
} 
free(content);


exit_d:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);

    mbedtls_exit(exit_code);




exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);


}

void gen_key(){
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
    fflush(stdout);

    if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP))      != 0) {
        mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
        goto exit;
    }

    if ((fpub = fopen("rsa_pub.txt", "wb+")) == NULL) {
        mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
        goto exit;
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpub)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpub)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
    fflush(stdout);

    if ((fpriv = fopen("rsa_priv.txt", "wb+")) == NULL) {
        mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
        goto exit;
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = ", &D, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = ", &P, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = ", &Q, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &DP, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &QP, 16, fpriv)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if (fpub  != NULL) {
        fclose(fpub);
    }

    if (fpriv != NULL) {
        fclose(fpriv);
    }

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

}


