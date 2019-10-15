#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>
#include "sig_api.h"
#include "rng.h"
#include "pkp_utils.h"
#include "kat.h"

int kat_check_keygen(unsigned char *pk, unsigned char *sk)
{
    size_t m = PKP_M, n = PKP_N, i;
    Vector *W, *Pi, *W_inv_Pi, *product;
    Matrix *A;
    pkp_pk_t *_pk = (pkp_pk_t *)pk;
    pkp_sk_t *_sk = (pkp_sk_t *)sk;
    Vector *last_column;
    BIGNUM *rnd;
    BN_CTX *bn_ctx;
    unsigned char *seed, *data;
    EVP_MD_CTX *shake256_ctx;

    if (m >= n)
        return -1;
    if ((shake256_ctx =EVP_MD_CTX_new()) == NULL){
        return -1;
    }
    if ((seed = malloc(PKP_SEED_SIZE)) == NULL)
        return -1;

    if ((rnd = BN_new()) == NULL)
        return -1;
    if ((bn_ctx = BN_CTX_new()) == NULL){
        return -1;
    }
    if ((W_inv_Pi = malloc_vector(n)) == NULL)
        return -1;
    if ((A = malloc_matrix(m, n)) == NULL)
        return -1;

    if (init_matrix_id_random(A, PKP_P, _pk->seed, PKP_SEED_SIZE, bn_ctx))
        return -1;

    if (BN_bin2bn(_pk->last_column, sizeof(_pk->last_column), rnd) == NULL) {
        handleErrors();
        return -1;
    }
    if ((last_column = malloc_vector(A->row)) == NULL)
        return -1;

    if (bn2vector(rnd, last_column, PKP_P, 0))
        return -1;

    for (i = 0; i < m; i++) {
         A->data[i][n - 1] = last_column->data[i];
    }
    free_vector(last_column);

    if ((Pi = malloc_vector(n)) == NULL)
        return -1;
    /* get Pi seed */
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, _sk->seed, sizeof(_sk->seed)) != 1) {
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, KEYGEN_SEED_A, sizeof(KEYGEN_SEED_A)) != 1) {
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, seed, PKP_SEED_SIZE) != 1) {
        handleErrors();
        return -1;
    }
    EVP_MD_CTX_free(shake256_ctx);

	if ((data = malloc(PKP_SEED_SIZE + sizeof(KEYGEN_SEED_PI))) == NULL)
		return -1;
	/* generate secret permutation Pi */
	memcpy(data, seed, PKP_SEED_SIZE);
	memcpy(data + PKP_SEED_SIZE, KEYGEN_SEED_PI, sizeof(KEYGEN_SEED_PI));
    gen_permutation_bn(data, PKP_SEED_SIZE+sizeof(KEYGEN_SEED_PI), Pi, !SAVE_BN, NULL, bn_ctx);
	free(seed);
	free(data);

    if (BN_bin2bn(_pk->V, sizeof(_pk->V), rnd) == NULL)
        return -1;

    if (bn2vector(rnd, W_inv_Pi, PKP_P, 0))
        return -1;

    W = permute_vector(W_inv_Pi, Pi);
    if (W == NULL) {
        return -1;
    };

	if ((product = malloc_vector(PKP_M))== NULL)
		return -1;
    /* Make sure vector W is the kernel of matrix A*/
    if (matrix_vector_product(product, A, W, PKP_P))
		return -1;

    for (i = 0; i < product->size; i++) {
        if(product->data[i] != 0)
            return -1;
    }

    free_vector(product);
    BN_CTX_free(bn_ctx);
    BN_free(rnd);
    free_matrix(A);
    free_vector(W);
    free_vector(W_inv_Pi);
    free_vector(Pi);
    return 0;
}

int generate_kat_files()
{
    char                fn_req[32], fn_rsp[32];
    FILE                *fp_req, *fp_rsp;
    int i,j;
    unsigned char       msg[3300];
    unsigned char       *m, *sm, seed[RNG_SEED_SIZE];
    unsigned long long  mlen, smlen;
    int                 count;
    int                 done;
    unsigned char *pk = malloc(SIG_PUBLICKEYBYTES);
    unsigned char *sk = malloc(SIG_SECRETKEYBYTES);

    sprintf(fn_req, "PQCsignKAT_%d.req", PKP_SECURITY_BITS);
    if ((fp_req = fopen(fn_req, "w")) == NULL) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    for (i = 0; i < 100; i++) {
        fprintf(fp_req, "count = %d\n", i);
        //tirage random?
        //sysrandom(seed, RNG_SEED_SIZE);
        //tirage pseudorandom?
        for (j = 0; j < RNG_SEED_SIZE; j++)
            seed[j] = (unsigned char)(i+j);
        fprintBstr(fp_req, (char*)"seed = ", seed, RNG_SEED_SIZE);

        mlen = 33 * (i + 1);
        fprintf(fp_req, "mlen = %llu\n", mlen);
        //tirage random?
        //sysrandom(msg, mlen);
        //tirage pseudorandom?
        for (j = 0; j < mlen; j++)
            msg[j] = (unsigned char)(33*i+j);
        fprintBstr(fp_req, (char*)"msg = ", msg, mlen);
    }
    fclose(fp_req);

    sprintf(fn_rsp, "PQCsignKAT_%d.rsp", PKP_SECURITY_BITS);
    if ((fp_rsp = fopen(fn_rsp, "w")) == NULL) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    if ((fp_req = fopen(fn_req, "r")) == NULL) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# %s\n\n", SIG_ALGNAME);
    done = 0;
    do {
        if (FindMarker(fp_req, "count = "))
            fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);

        if (!ReadHex(fp_req, seed, RNG_SEED_SIZE, (char*)"seed = ")) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, (char*)"seed = ", seed, RNG_SEED_SIZE);

        randombytes_init(seed, NULL);
        if (sig_keygen(pk, sk)) {
            fprintf(stderr, "Failed to generate keys\n");
            return -1;
        }
        fprintBstr(fp_rsp, (char*)"pk = ", pk, SIG_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, (char*)"sk = ", sk, SIG_SECRETKEYBYTES);
        // if (!ReadHex(fp_req, pk, SIG_PUBLICKEYBYTES, (char*)"pk = ")) {
        //     printf("ERROR: unable to read 'pk' from <%s>\n", fn_req);
        //     getchar();
        //     return KAT_DATA_ERROR;
        // }
        // fprintBstr(fp_rsp, (char*)"pk = ", pk, SIG_PUBLICKEYBYTES);

        // if (!ReadHex(fp_req, sk, SIG_SECRETKEYBYTES, (char*)"sk = ")) {
        //     printf("ERROR: unable to read 'sk' from <%s>\n", fn_req);
        //     getchar();
        //     return KAT_DATA_ERROR;
        // }

        // fprintBstr(fp_rsp, (char*)"sk = ", sk, SIG_SECRETKEYBYTES);

        if (kat_check_keygen(pk, sk)) {
            fprintf(stderr, "Failed to check generated keys\n");
            return -1;
        }
        else
        {
            fprintf(fp_rsp, "Check Generated keys Ok!\n");
        }

        if (FindMarker(fp_req, "mlen = "))
            fscanf(fp_req, "%llu", &mlen);
        else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %llu\n", mlen);

        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        sm = (unsigned char *)calloc(SIG_BYTES, sizeof(unsigned char));

        if (!ReadHex(fp_req, m, (int)mlen, (char*)"msg = ")) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, (char*)"msg = ", m, mlen);

        if (sig_sign(sk, m, mlen, sm, &smlen)) {
            fprintf(stderr, "Failed to sign\n");
            return -1;
        }
        fprintf(fp_rsp, "smlen = %llu\n", smlen);
        fprintBstr(fp_rsp, (char*)"sm = ", sm, smlen);

        // if (FindMarker(fp_req, "smlen = "))
        //     fscanf(fp_req, "%llu", &smlen);
        // else {
        //     printf("ERROR: unable to read 'smlen' from <%s>\n", fn_req);
        //     getchar();
        //     return KAT_DATA_ERROR;
        // }

        // if (!ReadHex(fp_req, sm, smlen, (char*)"sm = ")) {
        //     printf("ERROR: unable to read sm' from <%s>\n", fn_req);
        //     getchar();
        //     return KAT_DATA_ERROR;
        // }
        // fprintBstr(fp_rsp, (char*)"sm = ", sm, smlen);

        if (sig_verf(pk, sm, smlen, m, mlen)) {
            fprintf(stderr, "Failed to verify signed message\n");
            getchar();
            return -1;
        }
        fprintf(fp_rsp, "Check signature Ok!\n");
        free(m);
        free(sm);

    } while (!done);

    fclose(fp_req);
    fclose(fp_rsp);

    free(pk);
    free(sk);
    printf("KAT Ok!\n");

    return 0;
}


//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
    char	line[MAX_MARKER_LEN];
    int		i, len;
    int curr_line;

    len = (int)strlen(marker);
    if (len > MAX_MARKER_LEN - 1)
        len = MAX_MARKER_LEN - 1;

    for (i = 0; i < len; i++)
    {
        curr_line = fgetc(infile);
        line[i] = curr_line;
        if (curr_line == EOF)
            return 0;
    }
    line[len] = '\0';

    while (1) {
        if (!strncmp(line, marker, len))
            return 1;

        for (i = 0; i < len - 1; i++)
            line[i] = line[i + 1];
        curr_line = fgetc(infile);
        line[len - 1] = curr_line;
        if (curr_line == EOF)
            return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
    int			i, ch, started;
    unsigned char	ich;

    if (Length == 0) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if (FindMarker(infile, str))
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) {
                    if (ch == '\n')
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ((ch >= '0') && (ch <= '9'))
                ich = ch - '0';
            else if ((ch >= 'A') && (ch <= 'F'))
                ich = ch - 'A' + 10;
            else if ((ch >= 'a') && (ch <= 'f'))
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

            for (i = 0; i < Length - 1; i++)
                A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long  i;

    fprintf(fp, "%s", S);

    for (i = 0; i < L; i++)
        fprintf(fp, "%02X", A[i]);

    if (L == 0)
        fprintf(fp, "00");

    fprintf(fp, "\n");
}

