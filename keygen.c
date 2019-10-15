#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include "sig_api.h"
#include "pkp_utils.h"

int gen_keypair(unsigned char *sk_seed, unsigned char *pk, BN_CTX *bn_ctx,
               unsigned char* R_seed, unsigned char* Sigma_seed,
               Vector **_Pi, Vector **_V, Matrix **_A)
{
    Vector *W, *inv_Pi, *Pi, *W_inv_Pi, *product, *last_column;
    BIGNUM *random;
    Matrix *A;
    unsigned char *seed, *data;
    EVP_MD_CTX *shake256_ctx;
    pkp_pk_t *_pk = (pkp_pk_t *) pk;
    size_t i;

    if ((Pi = malloc_vector(PKP_N)) == NULL)
        return -1;
    if ((shake256_ctx = EVP_MD_CTX_new()) == NULL)
        return -1;
    if ((W = malloc_vector(PKP_N)) == NULL)
        return -1;
    if ((A = malloc_matrix(PKP_M, PKP_N)) == NULL)
        return -1;
    if ((random = BN_new()) == NULL)
        return -1;
    if ((seed = malloc(PKP_SEED_SIZE*5)) == NULL)
        return -1;

    /* Generate 5 seeds, 3 for Pi, W, A, and 2 for sig*/
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, sk_seed, PKP_SEED_SIZE) != 1) {
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, KEYGEN_SEED_A, sizeof(KEYGEN_SEED_A)) != 1) {
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, seed, PKP_SEED_SIZE*5) != 1) {
        return -1;
    }

	if ((data = malloc(PKP_SEED_SIZE + sizeof(KEYGEN_SEED_PI) + sizeof(KEYGEN_SEED_W))) == NULL)
		return -1;
    /* generate secret permutation Pi */
	memcpy(data, seed, PKP_SEED_SIZE);
	memcpy(data+PKP_SEED_SIZE, KEYGEN_SEED_PI, sizeof(KEYGEN_SEED_PI));
    if (gen_permutation_bn(data, PKP_SEED_SIZE + sizeof(KEYGEN_SEED_PI),
						   Pi, !SAVE_BN, NULL, bn_ctx))
        return -1;
    if (_Pi)
        *_Pi = Pi;

    if ((inv_Pi = malloc_vector(PKP_N)) == NULL){
        return -1;
    }
    if (inverse_permutation(Pi, inv_Pi))
        return -1;

    memcpy(data, seed + PKP_SEED_SIZE, PKP_SEED_SIZE);
    memcpy(data + PKP_SEED_SIZE, KEYGEN_SEED_W, sizeof(KEYGEN_SEED_W));
    /* generate W->size elements within PKP_P-1 */
    if (gen_unique_randoms_bn(data, PKP_SEED_SIZE+sizeof(KEYGEN_SEED_W), W, PKP_P-1, bn_ctx))
        return -1;
    free(data);
    /* make sure W is within 1-P */
    for (i=0; i<W->size; i++)
        W->data[i] += 1;

    if ((W_inv_Pi = permute_vector(W, inv_Pi)) == NULL)
        return -1;
    /* save V */
    if (_V)
        *_V = W_inv_Pi;

    if (init_matrix_id_random(A, PKP_P, seed+PKP_SEED_SIZE*2, PKP_SEED_SIZE, bn_ctx))
        return -1;
    memcpy(_pk->seed, seed+PKP_SEED_SIZE*2, sizeof(_pk->seed));

    if (init_kern_vector(A, W, PKP_P, bn_ctx))
        return -1;

    /* Make sure vector W is the kernel of matrix A*/
	if ((product = malloc_vector(PKP_M)) == NULL)
		return -1;
	/* Make sure vector W is the kernel of matrix A*/
	if (matrix_vector_product(product, A, W, PKP_P))
		return -1;

    for (i=0; i<product->size; i++) {
        assert(product->data[i] == 0);
    }
    free_vector(product);
    /* save A */
    if (_A)
        *_A = A;

    /* step 9 public key, secret key keeps a copy of this too*/
    if ((last_column = malloc_vector(A->row)) == NULL)
        return -1;
    for (i=0; i<PKP_M; i++) {
        last_column->data[i] = A->data[i][PKP_N-1];
    }
    /* convert vector to BN */
    if (vector2bn(last_column, PKP_P, random))
        return -1;
    free_vector(last_column);

    if (BN_bn2binpad(random, _pk->last_column, sizeof(_pk->last_column)) == -1)
        return -1;

    /* convert vector to BN */
    if (vector2bn(W_inv_Pi, PKP_P, random))
        return -1;
    if (BN_bn2binpad(random, _pk->V, sizeof(_pk->V)) == -1)
        return -1;
    BN_free(random);

    if (R_seed)
        memcpy(R_seed, seed+PKP_SEED_SIZE*3, PKP_SEED_SIZE);
    if (Sigma_seed)
        memcpy(Sigma_seed, seed+PKP_SEED_SIZE*4, PKP_SEED_SIZE);

    free(seed);
    free_vector(W);
    free_vector(inv_Pi);
    EVP_MD_CTX_free(shake256_ctx);
    if (_Pi == NULL)
        free_vector(Pi);
    if (_A == NULL)
        free_matrix(A);
    if (_V == NULL)
        free_vector(W_inv_Pi);

    return 0;
}

int sig_keygen(unsigned char *pk, unsigned char *sk)
{
    pkp_sk_t *_sk = (pkp_sk_t *) sk;
    BN_CTX *bn_ctx;

    if ((bn_ctx = BN_CTX_new()) == NULL)
        return -1;

    randombytes(_sk->seed, sizeof(_sk->seed));
#ifdef DEBUG
	memset(_sk->seed, 0, sizeof(_sk->seed));
#endif

    if (gen_keypair(_sk->seed, pk, bn_ctx, NULL, NULL, NULL, NULL, NULL))
        return -1;

    BN_CTX_free(bn_ctx);

    return 0;
}
