#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "sig_api.h"
#include "pkp_utils.h"

int sig_sign(unsigned char *sk, unsigned char *m, unsigned long long mlen,
    unsigned char *sm, unsigned long long *smlen)
{
    unsigned char *data, hash[HASH_SIZE], *random_bytes, Sign0[HASH_SIZE];
    unsigned char _R_seed[PKP_SEED_SIZE], _Sigma_seed[PKP_SEED_SIZE];
    unsigned char *C_0[ROUNDS], *C_1[ROUNDS], *Sigma_seeds, *R_seeds;
    Vector *R[ROUNDS], *Sigma[ROUNDS], *Pi_Sigma[ROUNDS], *R_Sigma[ROUNDS], *Z[ROUNDS];
    Vector *tmp, *Pi, *V, *Ch_0, *sigma_inv;
#ifdef OPTIM_BEULLENS
	size_t i;
#else
	size_t i, pos;
#endif
    pkp_sig_t *sig = (pkp_sig_t *) sm;
    pkp_sk_t *_sk = (pkp_sk_t *) sk;
    pkp_pk_t *_pk;
    Matrix *A;
    EVP_MD_CTX *shake256_ctx;
    BN_CTX *bn_ctx;
    BIGNUM *random;

    if ((bn_ctx = BN_CTX_new()) == NULL){
		fprintf(stderr, "Failed BN_CTX_new\n");
		return -1;
    }
    if ((random = BN_new()) == NULL){
		fprintf(stderr, "Failed to allocate memory for BN_new\n");
		return -1;
    }
    if ((shake256_ctx = EVP_MD_CTX_new()) == NULL){
		fprintf(stderr, "Failed to allocate memory for EVP_MD_CTX_new\n");
		return -1;
    }

	if ((_pk = malloc(sizeof(pkp_pk_t))) == NULL) {
		fprintf(stderr, "Failed to allocate memory for malloc\n");
		return -1;
	}
	/* regenerate keys */
	if (gen_keypair(_sk->seed, (unsigned char *)_pk, bn_ctx, _R_seed, _Sigma_seed, &Pi, &V, &A)) {
		fprintf(stderr, "Failed gen_keypair\n");
		return -1;
	}
#ifdef DEBUG
	dump_vector("sign V", V, -1);
#endif

	/* produce R = Hash(sk,m) */

    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, sk, SIG_SECRETKEYBYTES) != 1) {
		fprintf(stderr, "Failed EVP\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, m, mlen) != 1) {
		fprintf(stderr, "Failed EVP\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, hash, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP\n");
		handleErrors();
        return -1;
    }

    /* copy R as the first part of sm */
    memcpy(sig->R, hash, HASH_SIZE);
#ifdef DEBUG
	dump_mem("sign sig->R", sig->R, -1, HASH_SIZE);
#endif

    /* step 3, hash = D = Hash( pk, R, m) */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, _pk, SIG_PUBLICKEYBYTES) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, hash, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, m, mlen) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, hash, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
		handleErrors();
        return -1;
    }
    free(_pk);
#ifdef DEBUG
	dump_mem("sign D", hash, -1, HASH_SIZE);
#endif

    /* step 4 */
	if ((data = malloc(PKP_SEED_SIZE + HASH_SIZE)) == NULL) {
		fprintf(stderr, "Failed to allocate memory for malloc\n");
		return -1;
	}
     /* R.seed */
    if ((R_seeds = malloc(PKP_SEED_SIZE*ROUNDS)) == NULL){
		fprintf(stderr, "Failed to allocate memory for malloc\n");
		return -1;
    }
	/* generate R_seeds */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
		handleErrors();
		return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, _R_seed, PKP_SEED_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
		return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, SIGN_SEED_R, sizeof(SIGN_SEED_R)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
		return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, R_seeds, PKP_SEED_SIZE*ROUNDS) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
		return -1;
    }
#ifdef DEBUG
//	dump_mem("sign R_seeds", R_seeds, -1, PKP_SEED_SIZE*ROUNDS);
#endif

    for (i=0; i<ROUNDS; i++) {
#ifdef OPTIM_BEULLENS
		/* generate R_sigma[i]  instead of R[i] */
		if ((R_Sigma[i] = malloc_vector(PKP_N)) == NULL) {
			fprintf(stderr, "Failed to allocate memory for malloc_vector\n");
			return -1;
		}
		memcpy(data, R_seeds + i * PKP_SEED_SIZE, PKP_SEED_SIZE);
		memcpy(data + PKP_SEED_SIZE, hash, HASH_SIZE);
#ifdef DEBUG
		dump_mem("sign data R_seeds", data, i, PKP_SEED_SIZE + HASH_SIZE);
#endif
		if (gen_random_vector_bn(data, PKP_SEED_SIZE + HASH_SIZE,
			R_Sigma[i], SAVE_BN, NULL, PKP_P, 0, bn_ctx)){
			fprintf(stderr, "Failed gen_random_vector_bn\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign R_Sigma", R_Sigma[i], i);
#endif
#else
		/* generate R[i] */
		if ((R[i] = malloc_vector(PKP_N)) == NULL) {
			fprintf(stderr, "Failed to allocate memory for malloc_vector\n");
            return -1;
		}
        memcpy(data, R_seeds+i*PKP_SEED_SIZE, PKP_SEED_SIZE);
        memcpy(data+PKP_SEED_SIZE, hash, HASH_SIZE);
		if (gen_random_vector_bn(data, PKP_SEED_SIZE + HASH_SIZE,
			R[i], !SAVE_BN, NULL, PKP_P, 0, bn_ctx)) {
			fprintf(stderr, "Failed gen_random_vector_bn\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign R", R[i], i);
#endif
#endif
    }

    /* step 5 */

	if ((Sigma_seeds = malloc(PKP_SEED_SIZE*ROUNDS)) == NULL) /* Sigma.seed */ {
		fprintf(stderr, "Failed to allocate memory for malloc\n");
        return -1;
	}
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
		handleErrors();
		return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, _Sigma_seed, PKP_SEED_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
		return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, SIGN_SEED_SIGMA, sizeof(SIGN_SEED_SIGMA)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
		return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, Sigma_seeds, PKP_SEED_SIZE*ROUNDS) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
		handleErrors();
		return -1;
    }
    for (i=0; i<ROUNDS; i++) {
		/* generate Sigma[i]*/
		if ((Sigma[i] = malloc_vector(PKP_N)) == NULL) {
			fprintf(stderr, "Failed to allocate memory for malloc_vector\n");
			return -1;
		}
#ifdef DEBUG
		dump_mem("sign Sigma_seeds", Sigma_seeds + i * PKP_SEED_SIZE, i, PKP_SEED_SIZE);
#endif

        memcpy(data, Sigma_seeds+i*PKP_SEED_SIZE, PKP_SEED_SIZE);
        memcpy(data+PKP_SEED_SIZE, hash, HASH_SIZE);
		if (gen_permutation_bn(data, PKP_SEED_SIZE + HASH_SIZE,
			Sigma[i], SAVE_BN, NULL, bn_ctx)) {
			fprintf(stderr, "Failed gen_permutation_bn\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign Sigma", Sigma[i], i);
#endif
	}
	free(data);

    /* step 6 */
	if ((data = malloc(FACTORIAL_N_SIZE + POWER_P_N_SIZE)) == NULL) {
		fprintf(stderr, "Failed to allocate memory for malloc\n");
		return -1;
	}
	if ((tmp = malloc_vector(PKP_M)) == NULL) {
		fprintf(stderr, "Failed to allocate memory for malloc_vector\n");
		return -1;
	}
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
		handleErrors();
		return -1;
    }
	if ((sigma_inv = malloc_vector(PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
		return -1;
	}
	for (i=0; i<ROUNDS; i++) {
        C_0[i] = malloc(HASH_SIZE);
        if (C_0[i] == NULL) {
            fprintf(stderr, "Failed to allocate memory for C_0[%zu]\n", i);
            return -1;
        }

        C_1[i] = malloc(HASH_SIZE);
        if (C_1[i] == NULL) {
            fprintf(stderr, "Failed to allocate memory for C_1[%zu]\n", i);
            return -1;
        }
        /* step 7 */

#ifdef OPTIM_BEULLENS
		if (BN_bn2binpad(Sigma[i]->bn, data, FACTORIAL_N_SIZE) == -1) {
			fprintf(stderr, "Failed BN_bn2binpad 1\n");
			return -1;
		}

		R[i] = unpermute_vector(R_Sigma[i], Sigma[i]);
		if (R[i] == NULL) {
			fprintf(stderr, "Failed permute_vector\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign R", R[i], i);
#endif
#else
		R_Sigma[i] = permute_vector(R[i], Sigma[i]);
		if (R_Sigma[i] == NULL) {
			fprintf(stderr, "Failed permute_vector\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign R_Sigma", R_Sigma[i], i);
#endif

#endif
		/* A * R */
		if (matrix_vector_product(tmp, A, R[i], PKP_P)) {
			fprintf(stderr, "Failed matrix_vector_product\n");
			return -1;
		}

#ifdef DEBUG
		dump_vector("sign A * R", tmp, i);
#endif
		/* regenerate the BN and its bytes representation */
		if (vector2bn(tmp, PKP_P, random)) {
			fprintf(stderr, "Failed vector2bn\n");
            return -1;
		}
		if (BN_bn2binpad(random, data + FACTORIAL_N_SIZE, POWER_P_M_SIZE) == -1) {
			fprintf(stderr, "Failed BN_bn2binpad 7\n");
            return -1;
		}
		if (BN_bn2binpad(Sigma[i]->bn, data, FACTORIAL_N_SIZE) == -1) {
			fprintf(stderr, "Failed BN_bn2binpad\n");
			return -1;
		}
		/* C_0 = Hash( Sigma | A*R) */
#ifdef DEBUG
		dump_mem("sign data C_0", data, i, FACTORIAL_N_SIZE + POWER_P_M_SIZE);
#endif
		if (SHAKE256(C_0[i], HASH_SIZE, data, FACTORIAL_N_SIZE + POWER_P_M_SIZE)) {
			fprintf(stderr, "Failed SHAKE256\n");
            return -1;
		}
#ifdef DEBUG
		dump_mem("sign C_0", C_0[i], i, HASH_SIZE);
#endif

        /* step 8 */
        Pi_Sigma[i] = permutation_mul(Pi, Sigma[i]);
		if (Pi_Sigma[i] == NULL) {
			fprintf(stderr, "Failed permutation_mul\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign Pi_Sigma", Pi_Sigma[i], i);
#endif
		/* regenerate BIGNUM and its bytes representation */
		if (permutation2bn(Pi_Sigma[i], random)) {
			fprintf(stderr, "Failed permutation2bn\n");
            return -1;
		}
		if ((Pi_Sigma[i]->bn = BN_dup(random)) == NULL) {
			fprintf(stderr, "Failed BN_dup\n");
            return -1;
		}
		if (BN_bn2binpad(random, data, FACTORIAL_N_SIZE) == -1) {
			fprintf(stderr, "Failed BN_bn2binpad 2\n");
            return -1;
		}
		/* regenerate BIGNUM and its bytes representation */
		if (vector2bn(R_Sigma[i], PKP_P, random)) {
			fprintf(stderr, "Failed vector2bn\n");
            return -1;
		}
		if (BN_bn2binpad(random, data + FACTORIAL_N_SIZE, POWER_P_N_SIZE) == -1) {
			fprintf(stderr, "Failed BN_bn2binpad 3\n");
            return -1;
		}
#ifdef DEBUG
		dump_mem("sign data C_1", data, i, FACTORIAL_N_SIZE + POWER_P_N_SIZE);
#endif
		if (SHAKE256(C_1[i], HASH_SIZE, data, FACTORIAL_N_SIZE + POWER_P_N_SIZE)) {
			fprintf(stderr, "Failed SHAKE256\n");
            return -1;
		}
#ifdef DEBUG
		dump_mem("sign C_1", C_1[i], i, HASH_SIZE);
#endif



        /* step 9 */
        if (EVP_DigestUpdate(shake256_ctx, C_0[i], HASH_SIZE) != 1) {
			fprintf(stderr, "Failed EVP_DigestUpdate\n");
            handleErrors();
            return -1;
        }
        if (EVP_DigestUpdate(shake256_ctx, C_1[i], HASH_SIZE) != 1) {
			fprintf(stderr, "Failed EVP_DigestUpdate\n");
            handleErrors();
            return -1;
        }
    }
    free(data);
    free_vector(Pi);
    free_vector(tmp);
#ifdef OPTIM_BEULLENS
	free_vector(sigma_inv);
#else
#endif
    free_matrix(A);
	/* first commitment */
    /* step 11 */
    if (EVP_DigestFinalXOF(shake256_ctx, Sign0, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
        handleErrors();
        return -1;
    }

    /* copy Sign0 as the second part of sm */
    memcpy(sig->Sign0, Sign0, HASH_SIZE);
#ifdef DEBUG
	dump_mem("sign sig->Sign0", sig->Sign0, -1, HASH_SIZE);
#endif

    /* step 12 */
    data = malloc(HASH_SIZE*2);
	/* D = hash */
    memcpy(data, hash, HASH_SIZE); 
    memcpy(data+HASH_SIZE, Sign0, HASH_SIZE);

    /* step 13 */
	if ((Ch_0 = malloc_vector(ROUNDS)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
		return -1;
	}
#ifdef OPTIM_BEULLENS
	if (gen_random_vector_bn(data, HASH_SIZE * 2, Ch_0, SAVE_BN, NULL,
		PKP_P-1, 1, bn_ctx)) {
		fprintf(stderr, "Failed gen_random_vector_bn\n");
		return -1;
	}
#else
	if (gen_random_vector_bn(data, HASH_SIZE * 2, Ch_0, SAVE_BN, NULL,
		PKP_P, 0, bn_ctx)) {
		fprintf(stderr, "Failed gen_random_vector_bn\n");
		return -1;
	}
#endif
#ifdef DEBUG
	dump_vector("Sign Ch_0", Ch_0, -1);
#endif
	free(data);
    for (i=0; i<ROUNDS; i++) {
        /* step 15 */
        tmp = permute_vector(V, Pi_Sigma[i]);
		if (tmp == NULL) {
			fprintf(stderr, "Failed permute_vector\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign V * Pi_Sigma", tmp, i);
#endif
		vector_mod_scale(tmp, Ch_0->data[i], PKP_P);

#ifdef DEBUG
		dump_vector("sign c * V Pi_Sigma", tmp, i);
#endif
		Z[i] = vector_add(R_Sigma[i], tmp, PKP_P);
		if (Z[i] == NULL) {
			fprintf(stderr, "Failed vector_add\n");
			return -1;
		}
#ifdef DEBUG
		dump_vector("sign Z", Z[i], i);
#endif
		/* copy resp0 = Z as the third part of sm */
        /* regenerate BN and its bytes representation */
		if (vector2bn(Z[i], PKP_P, random)) {
			fprintf(stderr, "Failed vector2bn\n");
			return -1;
		}
		if (BN_bn2binpad(random, sig->Sign1[i], sizeof(sig->Sign1[i])) == -1) {
			fprintf(stderr, "Failed BN_bn2binpad 4\n");
			return -1;
		}
#ifdef DEBUG
		dump_mem("sign Bin Z", sig->Sign1[i], i, sizeof(sig->Sign1[i]));
#endif

        free_vector(tmp);
    }
	free_vector(Ch_0);
	free_vector(V);
    /* step 19 */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
        handleErrors();
        return -1;
    }
#ifdef DEBUG
//	dump_mem("sign Ch_1 D", hash, -1, HASH_SIZE);
#endif
	if (EVP_DigestUpdate(shake256_ctx, hash, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
#ifdef DEBUG
//	dump_mem("sign Ch_1 Sign0", Sign0, -1, HASH_SIZE);
#endif
	if (EVP_DigestUpdate(shake256_ctx, Sign0, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, sig->Sign1, sizeof(sig->Sign1)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    random_bytes = malloc(ROUNDS*sizeof(int));
    if (EVP_DigestFinalXOF(shake256_ctx, random_bytes, ROUNDS*sizeof(int)) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
        handleErrors();
        return -1;
    }
#ifdef DEBUG
	dump_mem("sign Ch_1 Bin", random_bytes, -1, ROUNDS * sizeof(int));
#endif
	/* step 20-29 */
#ifdef OPTIM_BEULLENS
#else
	pos = 0;
#endif
    for (i=0; i<ROUNDS; i++) {
        if (mod(*((int*)random_bytes+i),2) == 0) {
/*             if (BN_bn2binpad(Sigma[i]->bn, sig->Sign2_1[i], FACTORIAL_N_SIZE) == -1)
                return -1; */
#ifdef OPTIM_BEULLENS
			memcpy(sig->Sign2_1[i], Sigma_seeds + i * PKP_SEED_SIZE, PKP_SEED_SIZE);
#ifdef DEBUG
			dump_mem("sign 0 Sign2_1 Sigma seed", sig->Sign2_1[i], i, PKP_SEED_SIZE);
#endif
#else
			memcpy(sig->Sign2_1+pos, Sigma_seeds+i*PKP_SEED_SIZE, PKP_SEED_SIZE);
#ifdef DEBUG
			dump_mem("sign Sign2_1 seed", sig->Sign2_1 + pos, i, PKP_SEED_SIZE);
#endif
			pos += PKP_SEED_SIZE;
#endif
            memcpy(sig->Sign2_2[i], C_1[i], HASH_SIZE);
#ifdef DEBUG
			dump_mem("sign 0 Sign2_2 C_1", sig->Sign2_2[i], i, HASH_SIZE);
#endif
		} else {
/*             if (BN_bn2binpad(Pi_Sigma[i]->bn, sig->Sign2_1[i], FACTORIAL_N_SIZE) == -1)
                return -1; */
#ifdef OPTIM_BEULLENS
			memcpy(sig->Sign2_1[i], R_seeds + i * PKP_SEED_SIZE, PKP_SEED_SIZE);
#ifdef DEBUG
			dump_mem("sign 1 Sign2_1 R seed", sig->Sign2_1[i], i, PKP_SEED_SIZE);
#endif
#else
			if (BN_bn2binpad(Pi_Sigma[i]->bn, sig->Sign2_1 + pos, FACTORIAL_N_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad 6\n");
				return -1;
			}
#ifdef DEBUG
			dump_mem("sign Sign2_1 Pi_Sigma", sig->Sign2_1 + pos, i, FACTORIAL_N_SIZE);
#endif
            pos += FACTORIAL_N_SIZE;

#endif
			memcpy(sig->Sign2_2[i], C_0[i], HASH_SIZE);
#ifdef DEBUG
			dump_mem("sign 1 Sign2_2 C_0", sig->Sign2_2[i], i, HASH_SIZE);
#endif
		}
    }

#if defined OPTIM_BEULLENS
	*smlen = sizeof(pkp_sig_t);
#else
	*smlen = sizeof(pkp_sig_t) + pos;
#ifdef DEBUG
//	dump_mem("sign Sign2_1", sig->Sign2_1, -1, pos);
#endif
#endif



    free(random_bytes);
    for (i=0; i<ROUNDS; i++) {
        free_vector(R[i]);
        free_vector(Sigma[i]);
        free_vector(Pi_Sigma[i]);
        free_vector(R_Sigma[i]);
        free_vector(Z[i]);
        free(C_0[i]);
        free(C_1[i]);
    }
	free(R_seeds);
	free(Sigma_seeds);
    EVP_MD_CTX_free(shake256_ctx);
    BN_free(random);
    BN_CTX_free(bn_ctx);
    return 0;
}
