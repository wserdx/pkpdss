#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "sig_api.h"
#include "pkp_utils.h"

int sig_verf(unsigned char *pk, unsigned char *sm, unsigned long long smlen,
    unsigned char *m, unsigned long long mlen)
{
    pkp_pk_t *_pk = (pkp_pk_t *) pk;
    pkp_sig_t * sig = (pkp_sig_t *) sm;
    unsigned char *data, *data2, Ch_1[ROUNDS], D[HASH_SIZE], *random_bytes;
    unsigned char C_0[HASH_SIZE], C_1[HASH_SIZE], Sign0[HASH_SIZE];
#ifdef OPTIM_BEULLENS
	long long c_inv;
	Vector *R_Sigma;
#else
    size_t pos;
	Vector *tmp2;
    Matrix* A_Sigma;
#endif
    size_t i;
    Vector *Z, *Sigma, *V, *Pi_Sigma, *tmp, *Ch_0, *Sigma_inv;
    Matrix* A;
    EVP_MD_CTX *shake256_ctx;
    BN_CTX *bn_ctx;
    BIGNUM *random;
    unsigned char *seed;
    Vector *column;
#ifdef DEBUG
	dump_mem("verif sig->R", sig->R, -1, HASH_SIZE);
#endif

    if ((bn_ctx = BN_CTX_new()) == NULL) {
		fprintf(stderr, "Failed BN_CTX_new\n");
		return -1;
    }
    if ((random = BN_new()) == NULL) {
		fprintf(stderr, "Failed BN_new\n");
		return -1;
    }
    if ((shake256_ctx =EVP_MD_CTX_new()) == NULL){
		fprintf(stderr, "Failed EVP_MD_CTX_new\n");
		return -1;
    }

	if ((seed = malloc(PKP_SEED_SIZE)) == NULL) {
		fprintf(stderr, "Failed malloc\n");
		return -1;
	}

	if ((V = malloc_vector(PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
        return -1;
	}

	if (BN_bin2bn(_pk->V, sizeof(_pk->V), random) == NULL) {
		fprintf(stderr, "Failed BN_bin2bn\n");
        return -1;
	}

	if (bn2vector(random, V, PKP_P, 0)) {
		fprintf(stderr, "Failed bn2vector\n");
        return -1;
	}
#ifdef DEBUG
	dump_vector("verif V", V, -1);
#endif

	if ((A = malloc_matrix(PKP_M, PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_matrix\n");
        return -1;
	}

    init_matrix_id_random(A, PKP_P, _pk->seed, PKP_SEED_SIZE, bn_ctx);
    /* convert BN to vector */
    if (BN_bin2bn(_pk->last_column, sizeof(_pk->last_column), random) == NULL) {
		fprintf(stderr, "Failed BN_bin2bn\n");
        return -1;
    }
	if ((column = malloc_vector(A->row)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
        return -1;
	}
	if (bn2vector(random, column, PKP_P, 0)) {
		fprintf(stderr, "Failed bn2vector\n");
        return -1;
	}
    for (i=0; i<PKP_M; i++) {
        A->data[i][PKP_N-1] = column->data[i];
    }

    /* step 2 */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, pk, SIG_PUBLICKEYBYTES) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, sig->R, sizeof(sig->R)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
		handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, m, mlen) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, D, HASH_SIZE) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
        handleErrors();
        return -1;
    }
#ifdef DEBUG
	dump_mem("verif D", D, -1, HASH_SIZE);
#endif

    /* step 3 */
	if ((data = malloc(HASH_SIZE * 2)) == NULL) {
		fprintf(stderr, "Failed malloc\n");
        return -1;
	}
    memcpy(data, D, HASH_SIZE);
    memcpy(data+HASH_SIZE, sig->Sign0, HASH_SIZE);

    /* step 4 */
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
	dump_vector("verif Ch_0", Ch_0, -1);
#endif
	free(data);
    random_bytes = malloc(ROUNDS*sizeof(int));

    /* step 5 */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, D, sizeof(D)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, sig->Sign0, sizeof(sig->Sign0)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, sig->Sign1, sizeof(sig->Sign1)) != 1) {
		fprintf(stderr, "Failed EVP_DigestUpdate\n");
        handleErrors();
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, random_bytes, ROUNDS*sizeof(int)) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
        handleErrors();
        return -1;
    }
#ifdef DEBUG
	dump_mem("verif Ch_1 Bin", random_bytes, -1, ROUNDS * sizeof(int));
#endif

    /* step 6 */
#ifdef OPTIM_BEULLENS
#else
	pos = 0;
#endif
    for (i=0; i<ROUNDS; i++) {
        Ch_1[i] = mod(*((int*)random_bytes+i), 2);
#ifdef OPTIM_BEULLENS
#else
		if (Ch_1[i] == 0)
            pos += PKP_SEED_SIZE;
        else
            pos += FACTORIAL_N_SIZE;
#endif
    }
#ifdef DEBUG
	dump_mem("verif Ch_1", Ch_1, -1, ROUNDS);
#endif
	free(random_bytes);
#ifdef OPTIM_BEULLENS
	if (smlen != sizeof(pkp_sig_t)) {
		fprintf(stderr, "The signature message's lengh is not correct\n");
		return -1;
	}
#else
	if (smlen < sizeof(pkp_sig_t) + pos) {
        fprintf(stderr, "The signature message's lengh is not correct\n");
        return -1;
    }
#endif

	if ((Z = malloc_vector(PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
		return -1;
	}
#ifdef OPTIM_BEULLENS
	if ((R_Sigma = malloc_vector(PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
		return -1;
	}
#endif
	if ((Sigma = malloc_vector(PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
		return -1;
	}
	if ((Sigma_inv = malloc_vector(PKP_N)) == NULL) {
		fprintf(stderr, "Failed malloc_vector\n");
		return -1;
	}
	if ((Pi_Sigma = malloc_vector(PKP_N)) == NULL) {

		fprintf(stderr, "Failed malloc_vector\n");
        return -1;
	}
	if ((data = malloc(FACTORIAL_N_SIZE + POWER_P_N_SIZE)) == NULL) {
		fprintf(stderr, "Failed malloc\n");

        return -1;
	}
	if ((data2 = malloc(PKP_SEED_SIZE + HASH_SIZE)) == NULL) {
 		fprintf(stderr, "Failed malloc\n");
		return -1;
	}

	/* Context pour Sign0 */
    /* step 9 */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
 		fprintf(stderr, "Failed EVP_DigestInit_ex\n");
        handleErrors();
        return -1;
    }
#ifdef OPTIM_BEULLENS
#else
	pos = 0;
#endif
    for (i=0; i<ROUNDS; i++) {
        /* step 10 */
		/* Read Z in signature */
        if (BN_bin2bn(sig->Sign1[i], sizeof(sig->Sign1[i]), random) == NULL) {
 			fprintf(stderr, "Failed BN_bin2bn\n");
            handleErrors();
            return -1;
        }
		if (bn2vector(random, Z, PKP_P, 0)) {
 			fprintf(stderr, "Failed bn2vector\n");
            return -1;
		}
#ifdef DEBUG
		dump_vector("verif Z", Z, i);
#endif
		/* step 11 */
        if (Ch_1[i] == 0) {
            /* step 12 */
#ifdef OPTIM_BEULLENS

			/* Read Sigma_seed */
			memcpy(data2, sig->Sign2_1[i], PKP_SEED_SIZE);
			memcpy(data2 + PKP_SEED_SIZE, D, HASH_SIZE);

#ifdef DEBUG
			dump_mem("verif sig->Sign2_1[i] sigma seed", sig->Sign2_1[i], i, PKP_SEED_SIZE);
#endif
			if (gen_permutation_bn(data2, PKP_SEED_SIZE + HASH_SIZE, Sigma, SAVE_BN, NULL, bn_ctx)) {
				fprintf(stderr, "Failed gen_permutation_bn\n");
				return -1;
			}
#ifdef DEBUG
			dump_vector("verif Sigma", Sigma, i);
#endif
			if (inverse_permutation(Sigma, Sigma_inv)) {
				fprintf(stderr, "Failed inverse_permutation\n");
				return -1;
			}
			/* Permute Z * Sigma_inv */
			tmp = permute_vector(Z, Sigma_inv);
			if (tmp == NULL) {
				fprintf(stderr, "Failed permute_vector\n");
				return -1;
			}
			if (matrix_vector_product(column, A, tmp, PKP_P)) {
				fprintf(stderr, "Failed matrix_vector_product\n");
				return -1;
			}
			free_vector(tmp);
			/* regenerate the BN and its bytes representation */
			if (vector2bn(column, PKP_P, random)) {
				fprintf(stderr, "Failed vector2bn\n");
				return -1;
			}
			if (BN_bn2binpad(random, data + FACTORIAL_N_SIZE, POWER_P_M_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad v1\n");
				return -1;
			}
			if (BN_bn2binpad(Sigma->bn, data, FACTORIAL_N_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad v2\n");
				return -1;
			}
			/* C_0 = Hash( sigma | A * Z sigma_inv ) */
#ifdef DEBUG
			dump_mem("verif 0 data", data, i, FACTORIAL_N_SIZE + POWER_P_M_SIZE);
#endif
			if (SHAKE256(C_0, HASH_SIZE, data, FACTORIAL_N_SIZE + POWER_P_M_SIZE)) {
				fprintf(stderr, "Failed SHAKE256\n");
				return -1;
			}
#else
#ifdef DEBUG
			dump_mem("verif Sigma_seed", sig->Sign2_1 + pos, i, PKP_SEED_SIZE);
#endif
			memcpy(data2, sig->Sign2_1 + pos, PKP_SEED_SIZE);
            pos += PKP_SEED_SIZE;
			memcpy(data2 + PKP_SEED_SIZE, D, HASH_SIZE);

			if (gen_permutation_bn(data2, PKP_SEED_SIZE + HASH_SIZE, Sigma, SAVE_BN, NULL, bn_ctx)) {
				fprintf(stderr, "Failed gen_permutation_bn\n");
				return -1;
			}
#ifdef DEBUG
			dump_vector("verif Sigma", Sigma, i);
#endif
            /* step 13 */
            A_Sigma = permute_matrix(A, Sigma);
			if (matrix_vector_product(column, A_Sigma, Z, PKP_P)) {
				fprintf(stderr, "Failed matrix_vector_product\n");
				return -1;
			}
#ifdef DEBUG
			dump_vector("verif (A_sigma * Z)", column, i);
#endif
			/* regenerate BN and its bytes representation */
			if (vector2bn(column, PKP_P, random)) {
				fprintf(stderr, "Failed matrix_vector_product\n");
                return -1;
			}
			if (BN_bn2binpad(random, data + FACTORIAL_N_SIZE, POWER_P_M_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad\n");
				return -1;
			}
			if (BN_bn2binpad(Sigma->bn, data, FACTORIAL_N_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad\n");
				return -1;
			}

			if (SHAKE256(C_0, HASH_SIZE, data, FACTORIAL_N_SIZE + POWER_P_M_SIZE)) {
				fprintf(stderr, "Failed SHAKE256\n");
                return -1;
			}
#ifdef DEBUG
			dump_mem("verif 0 Sign0 C_0", C_0, i, HASH_SIZE);
			dump_mem("verif 0 Sign0 sig->Sign2_2", sig->Sign2_2[i], i, sizeof(sig->Sign2_2[i]));
#endif

            free_matrix(A_Sigma);
#endif
			/* Aggregation Sign0 */
            /* step 18 */
            if (EVP_DigestUpdate(shake256_ctx,  C_0, sizeof(C_0)) != 1) {
				fprintf(stderr, "Failed EVP_DigestUpdate\n");
				handleErrors();
				return -1;
            }
            if (EVP_DigestUpdate(shake256_ctx,  sig->Sign2_2[i], sizeof(sig->Sign2_2[i])) != 1) {
				fprintf(stderr, "Failed EVP_DigestUpdate\n");
				handleErrors();
                return -1;
            }
#ifdef DEBUG
			dump_mem("verif 0 Sign0 C_0", C_0, i, HASH_SIZE);
			dump_mem("verif 0 Sign0 sig->Sign2_2", sig->Sign2_2[i], i, sizeof(sig->Sign2_2[i]));
#endif
		} else { //(Ch_1[i] == 1)
#if defined OPTIM_BEULLENS
			/* Read R_seed */
			memcpy(data2, sig->Sign2_1[i], PKP_SEED_SIZE);
			memcpy(data2 + PKP_SEED_SIZE, D, HASH_SIZE);
#ifdef DEBUG
			dump_mem("verif data R_seeds", data2, i, PKP_SEED_SIZE + HASH_SIZE);
#endif
			if (gen_random_vector_bn(data2, PKP_SEED_SIZE + HASH_SIZE,
				R_Sigma, SAVE_BN, NULL, PKP_P, 0, bn_ctx)) {
				fprintf(stderr, "Failed gen_random_vector_bn\n");
				return -1;
			}
#ifdef DEBUG
			dump_vector("verif 1 R_Sigma", R_Sigma, i);
#endif
			/* compute (Z - R Sigma) / c */
			tmp = vector_sub(Z, R_Sigma, PKP_P);
			c_inv = mod_mul_inverse(Ch_0->data[i], PKP_P, bn_ctx);
			vector_mod_scale(tmp, c_inv, PKP_P);
#ifdef DEBUG
			dump_vector("verif 1 V Pi Sigma", tmp, i);
			dump_vector("verif 1 V tmp", V, i);
#endif
			if (inverse_vector_permutation(V,tmp,Pi_Sigma)) {
				fprintf(stderr, "Failed inverse_vector_permutation\n");
				return -1;
			}
#ifdef DEBUG
			dump_vector("verif 1 Pi_Sigma", Pi_Sigma, i);
#endif
			free(tmp);
			/* regenerate BN and its bytes representation */
			if (permutation2bn(Pi_Sigma, random)) {
				fprintf(stderr, "Failed vector2bn\n");
				return -1;
			}
			if (BN_bn2binpad(random, data, FACTORIAL_N_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad v3\n");
				return -1;
			}
			if (BN_bn2binpad(R_Sigma->bn, data + FACTORIAL_N_SIZE, POWER_P_N_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad v4\n");
				return -1;
			}
#ifdef DEBUG
			dump_mem("verif 1 data", data, i, FACTORIAL_N_SIZE + POWER_P_N_SIZE);
#endif
			if (SHAKE256(C_1, HASH_SIZE, data, FACTORIAL_N_SIZE + POWER_P_N_SIZE)) {
				fprintf(stderr, "Failed SHAKE256\n");
				return -1;
			}
#ifdef DEBUG
			dump_mem("verif 1 Sign0 sig->Sign2_2", sig->Sign2_2[i], i, sizeof(sig->Sign2_2[i]));
			dump_mem("verif 1 Sign0 C_1", C_1, i, HASH_SIZE);
#endif
#else
#ifdef DEBUG
			dump_mem("verif Bin Pi_Sigma", sig->Sign2_1 + pos, i, FACTORIAL_N_SIZE);
#endif
			if (BN_bin2bn(sig->Sign2_1+pos, FACTORIAL_N_SIZE, random) == NULL) {
				fprintf(stderr, "Failed BN_bin2bn\n");
                return -1;
            }
			if (bn2permutation(random, Pi_Sigma, bn_ctx)) {
				fprintf(stderr, "Failed bn2permutation\n");
                return -1;
			}
#ifdef DEBUG
			dump_vector("verif Pi_Sigma", Pi_Sigma, i);
#endif
			memcpy(data, sig->Sign2_1+pos, FACTORIAL_N_SIZE);
            pos += FACTORIAL_N_SIZE;

            tmp2 = permute_vector(V, Pi_Sigma);
#ifdef DEBUG
			dump_vector("verif V Pi_Sigma", tmp2, i);
#endif
			vector_mod_scale(tmp2, Ch_0->data[i], PKP_P);
#ifdef DEBUG
			dump_vector("verif c * V Pi_Sigma", tmp2, i);
#endif
			tmp = vector_sub(Z, tmp2, PKP_P);
			if (tmp == NULL) {
				fprintf(stderr, "Failed vector_sub\n");
                return -1;
			}
#ifdef DEBUG
			dump_vector("verif Z - c * V Pi_Sigma", tmp, i);
#endif
			/* regenerate BN and its bytes representation */
			if (vector2bn(tmp, PKP_P, random)) {
				fprintf(stderr, "Failed vector2bn\n");
                return -1;
			}
			if (BN_bn2binpad(random, data + FACTORIAL_N_SIZE, POWER_P_N_SIZE) == -1) {
				fprintf(stderr, "Failed BN_bn2binpad\n");
                return -1;
			}

			if (SHAKE256(C_1, HASH_SIZE, data, FACTORIAL_N_SIZE + POWER_P_N_SIZE)) {

				fprintf(stderr, "Failed SHAKE256\n");
                return -1;
			}

            free_vector(tmp2);
            free_vector(tmp);
#endif
			/* step 18 */
            if (EVP_DigestUpdate(shake256_ctx,  sig->Sign2_2[i], sizeof(sig->Sign2_2[i])) != 1) {
				fprintf(stderr, "Failed EVP_DigestUpdate\n");
                handleErrors();
                return -1;
            }
            if (EVP_DigestUpdate(shake256_ctx,  C_1, sizeof(C_1)) != 1) {
				fprintf(stderr, "Failed EVP_DigestUpdate\n");
                handleErrors();
                return -1;
            }
#ifdef DEBUG
			dump_mem("verif 1 Sign0 sig->Sign2_2", sig->Sign2_2[i], i, sizeof(sig->Sign2_2[i]));
			dump_mem("verif 1 Sign0 C_1", C_1, i, HASH_SIZE);
#endif
		}
    }
	free_vector(column);

    if (EVP_DigestFinalXOF(shake256_ctx, Sign0, sizeof(Sign0)) != 1) {
		fprintf(stderr, "Failed EVP_DigestFinalXOF\n");
        handleErrors();
    }
#ifdef DEBUG
	dump_mem("verif Sign0", Sign0, -1, sizeof(Sign0));
	dump_mem("verif sig->Sign0", sig->Sign0, -1, HASH_SIZE);
#endif

    free(data);
    free(data2);
    free(seed);
    free_matrix(A);
    free_vector(Z);
#if defined OPTIM_BEULLENS
	free_vector(R_Sigma);
#endif
    free_vector(V);
    free_vector(Sigma);
    free_vector(Sigma_inv);
    free_vector(Pi_Sigma);
    free_vector(Ch_0);
    BN_free(random);
    EVP_MD_CTX_free(shake256_ctx);
    BN_CTX_free(bn_ctx);

    return memcmp(Sign0, sig->Sign0, HASH_SIZE);
}
