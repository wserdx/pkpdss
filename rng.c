/*
 rng.c

 Created by Bassham, Lawrence E (Fed) on 8/29/17.
 Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
 */

#include <string.h>
#include "rng.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <assert.h>
#include <limits.h>

AES256_CTR_DRBG_struct  DRBG_ctx;

void    AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer);

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
}

/* Use whatever AES implementation you have. This uses AES from openSSL library
   key - 256-bit AES key
   ctr - a 128-bit plaintext value
   buffer - a 128-bit ciphertext value */
void
AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer)
{
    EVP_CIPHER_CTX *ctx;
	/* test */
    int len;

    /* XXX I put in commentary to remove a warning during the compilation XXX */
/*    int ciphertext_len;*/

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, buffer, &len, ctr, 16))
        handleErrors();
    /* XXX I put in commentary to remove a warning during the compilation XXX */
/*    ciphertext_len = len;*/

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string)
{
    unsigned char   seed_material[RNG_SEED_SIZE];
    size_t i;
    memcpy(seed_material, entropy_input, RNG_SEED_SIZE);
    if (personalization_string)
        for (i=0; i<RNG_SEED_SIZE; i++)
            seed_material[i] ^= personalization_string[i];
    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

void
randombytes_forget()
{
    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
    DRBG_ctx.reseed_counter = RNG_UNINIT;
}

int
randombytes(unsigned char *x, unsigned long long xlen)
{
    unsigned char   block[16];
    int             i = 0, j;

    while ( xlen > 0 ) {
        /* increment V */
        for (j=15; j>=0; j--) {
            if ( DRBG_ctx.V[j] == 0xff )
                DRBG_ctx.V[j] = 0x00;
            else {
                DRBG_ctx.V[j]++;
                break;
            }
        }
        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);
        if ( xlen > 15 ) {
            memcpy(x+i, block, 16);
            i += 16;
            xlen -= 16;
        }
        else {
            memcpy(x+i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;

    return RNG_SUCCESS;
}

void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V)
{
    unsigned char   temp[RNG_SEED_SIZE];
    size_t i, j;
    for (i=0; i<3; i++) {
        /* increment V */
        for (j=15; j>=0; j--) {
            if ( V[j] == 0xff )
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }

        AES256_ECB(Key, V, temp+16*i);
    }
    if ( provided_data != NULL )
        for (i=0; i<RNG_SEED_SIZE; i++)
            temp[i] ^= provided_data[i];
    memcpy(Key, temp, 32);
    memcpy(V, temp+32, 16);
}
/*
 * Generate a random int between min and mix (non-inclusive)
 * Must be initialized by randombytes_init
https://codereview.stackexchange.com/questions/159604/uniform-random-numbers-in-an-integer-interval-in-c
 */
int random_int(int min, int max)
{
    assert(min < max);
    unsigned long long range = max - min;
    unsigned long long rnd;
    unsigned long long chunkSize = ULLONG_MAX / range;
    unsigned long long endOfLastChunk = chunkSize * range;

    assert(DRBG_ctx.reseed_counter != RNG_UNINIT);

    do {
        randombytes((unsigned char*)&rnd, sizeof(rnd));
    } while(rnd >= endOfLastChunk);

    return (int) (min + rnd / chunkSize);
}

/*
 * use system dependant function to get random bytes
 */
int sysrandom(void *buf, size_t buflen)
{
#ifdef __linux__
    if (getrandom(buf, buflen, 0) == -1)
        return -1;
#else /* else __linux__ */
#ifdef _WIN32
    if (!RtlGenRandom((PVOID) buf, (ULONG) buflen))
        return -1;
#else /* else _WIN32 */
    #error Only linux builds are supported.
#endif /* end _WIN32 */
#endif /* end __linux__ */
    return 0;
}
