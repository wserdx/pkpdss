#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include "pkp_utils.h"
#include "rng.h"
#include "sig_api.h"
#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#include <windef.h>
#endif

Vector* malloc_vector(size_t size)
{
    Vector* v = (Vector*) malloc(sizeof(Vector));
    if (v == NULL) {
        fprintf(stderr, "Failed to alloc memory for vector\n");
        return NULL;
    }
    v->size = size;
    v->data = (long long*) calloc(size, sizeof(long long));
    v->bn = NULL;
    return v;
}

Vector* vector_add(Vector *a, Vector *b, long long p)
{
    size_t i;
    Vector* v;

    assert(a->size == b->size);
    v = malloc_vector(a->size);
    if (v == NULL) {
        return NULL;
    }
    for (i=0; i<a->size; i++) {
        v->data[i] = mod(a->data[i]+b->data[i], p);
    }
    return v;
}

Vector* vector_sub(Vector *a, Vector *b, long long p)
{
    size_t i;
    Vector* v;

    assert(a->size == b->size);
    v = malloc_vector(a->size);
    if (v == NULL) {
        return NULL;
    }
    for (i=0; i<a->size; i++) {
        v->data[i] = mod(a->data[i]-b->data[i], p);
    }
    return v;
}

void vector_mod_scale(Vector *a, long long b, long long p)
{
    size_t i;

    for (i=0; i<a->size; i++) {
        a->data[i] = mod(a->data[i]*b, p);
    }
}


int inverse_vector_permutation(Vector *v, Vector *z, Vector *sigma)
{
	// look for sigma such that v = z * sigma
	size_t i,j;
	/* Naive implementation */
	/* to be optimized !!!! */
	assert((v->size == z->size) && (v->size == sigma->size));
	for (i = 0; i < sigma->size; i++) {
		sigma->data[i] = sigma->size;
	}

	for (i = 0; i < v->size; i++) {
		for (j = 0; j < z->size; j++) {
			if (v->data[i] == z->data[j])
			{
				sigma->data[j] = i;
				break;
			}
		}
	}
	for (i = 0; i < sigma->size; i++) {
		if (sigma->data[i] == sigma->size)
		{
			return -1;
		}
	}
	return 0;
}

void free_vector(Vector* v)
{
    free(v->data);
    if (v->bn)
        BN_free(v->bn);
    free(v);
}

Matrix* malloc_matrix(size_t row, size_t column)
{
    size_t i;

    Matrix* m = (Matrix*) malloc(sizeof(Matrix));
    if (m == NULL) {
        fprintf(stderr, "Failed to alloc memory for matrix\n");
        return NULL;
    }
    m->row = row;
    m->column = column;
    m->data = (long long**) malloc(row*sizeof(long long*));
    if (m->data == NULL) {
        fprintf(stderr, "Failed to alloc memory for matrix data\n");
        return NULL;
    }
    for (i=0; i<row; i++) {
        m->data[i] = (long long*) calloc(column, sizeof(long long));
    }
    return m;
}

int matrix_vector_product(Vector* product, Matrix* m, Vector* v, long long p)
{
    size_t i,j;
    if (m->column != v->size)
		return -1;

    for (i=0; i<m->row; i++) {
		product->data[i] = 0;
        for(j=0; j<m->column; j++) {
            product->data[i] += m->data[i][j] * v->data[j];
        }
        product->data[i] = mod(product->data[i], p);
    }
    return 0;
}

void free_matrix(Matrix* m)
{
    size_t i;
    for (i=0; i<m->row; i++) {
        free(m->data[i]);
    }
    free(m->data);
    free(m);
}

void print_matrix(Matrix* m)
{
    size_t i,j;
    for (i=0; i<m->row; i++) {
        for (j=0; j<m->column-1; j++) {
            printf("%llu ", m->data[i][j]);
        }
        printf("%llu\n", m->data[i][j]);
    }
}

void print_vector(Vector* vector)
{
    size_t i;
    for (i=0; i<vector->size-1; i++) {
        printf("%llu ", vector->data[i]);
    }
    printf("%llu\n", vector->data[i]);
}

long long mod_mul_inverse(long long a, long long m, BN_CTX *ctx)
{
	BIGNUM *bn_a, *bn_m;
    long long res;

	BN_CTX_start(ctx);
    if ((bn_a = BN_CTX_get(ctx)) == NULL)
        return -1;
    if ((bn_m = BN_CTX_get(ctx)) == NULL)
        return -1;
    BN_set_word(bn_a, a);
    BN_set_word(bn_m, m);
    if (BN_mod_inverse(bn_a, bn_a, bn_m, ctx) == NULL)
        return -1;
    res = BN_get_word(bn_a);

    if (res == (BN_ULONG)-1)
        return -1;
    BN_CTX_end(ctx);
    return res;
}

int gen_random_bn(unsigned char *seed, size_t seed_len, BIGNUM *random,
                  size_t min_size, BIGNUM *base, BN_CTX *ctx)
{
    unsigned char *bytes;
    size_t size;

    size = min_size + SECURITY_MARGIN_BYTES;

    if ((bytes = malloc(size)) == NULL)
        return -1;

    if(SHAKE256(bytes, size, seed, seed_len))
        return -1;

    if (BN_bin2bn(bytes, size, random) == NULL) {
        fprintf(stderr, "Failed to convert random bytes to BN\n");
        return -1;
    }

    if (!BN_nnmod(random, random, base, ctx)) {
        fprintf(stderr, "Failed to calculate the modular of BN\n");
        return -1;
    }

    free(bytes);
    return 0;
}

int permutation2bn(Vector* vector, BIGNUM *random)
{
    size_t i;
	long long rnd;
	long long tmp;
    Vector *helper, *reversed, *remainders;

    assert(random != NULL);
    BN_set_word(random, 0);

    helper = malloc_vector(vector->size);
    if (helper == NULL)
        return -1;
    remainders = malloc_vector(vector->size);
    if (remainders == NULL)
        return -1;
    for (i=0; i<helper->size; i++) {
        helper->data[i] = i;
    }
	if ((reversed = malloc_vector(vector->size)) == NULL)
		return -1;
    if (inverse_permutation(helper, reversed))
        return -1;
    for (i=vector->size-1; i>0; i--) {
        tmp = vector->data[i];

        rnd = reversed->data[tmp];
        remainders->data[i] = rnd;
        /* update tracking vector and its inverse */
        helper->data[rnd] = helper->data[i];
        reversed->data[helper->data[i]] = rnd;

        helper->data[i] = tmp;
        reversed->data[tmp] = i;
    }
	free_vector(reversed);

    for (i=1; i<vector->size; i++) {
        if (!BN_mul_word(random, i+1))
            return -1;
        if (!BN_add_word(random, remainders->data[i]))
            return -1;
    }

    free_vector(helper);
    free_vector(remainders);
    return 0;
}

/* vector should already be initialized */
int bn2permutation(BIGNUM *random, Vector *vector, BN_CTX *ctx)
{
    size_t i;
    BN_ULONG rmndr, tmp;

    for (i=0; i<vector->size; i++) {
        vector->data[i] = i;
    }

    for (i=vector->size-1; i>0; i--) {
        if ((rmndr = BN_div_word(random, i+1)) == (BN_ULONG)-1)
            return -1;
        tmp = vector->data[rmndr];
        vector->data[rmndr] = vector->data[i];
        vector->data[i] = tmp;
    }
    return 0;
}

int gen_permutation_bn(unsigned char *seed, size_t seed_len,
                       Vector* vector, int save_bn,
                       BIGNUM* rnd, BN_CTX *ctx)
{
    BIGNUM *fac, *random;

    BN_CTX_start(ctx);
    if ((fac = BN_CTX_get(ctx)) == NULL)
        return -1;

    if (factorial(vector->size, fac))
        return -1;


    if (rnd == NULL) {
        if ((random = BN_CTX_get(ctx)) == NULL)
            return -1;
        if (gen_random_bn(seed, seed_len, random, BN_num_bytes(fac), fac, ctx))
            return -1;
    } else {
        random = rnd;
    }

    if (save_bn) {
        vector->bn = BN_dup(random);
        if (vector->bn == NULL)
            return -1;
    }

    if (bn2permutation(random, vector, ctx))
        return -1;

    BN_CTX_end(ctx);

    return 0;
}

int gen_unique_randoms_bn(unsigned char *seed, size_t seed_len,
                       Vector* vector, long long p,
                       BN_CTX *ctx)
{
    BIGNUM *fac, *random;
    long long tmp, rmndr;
    size_t i, size;
    Vector *vec_p;

    assert(p>vector->size);

    BN_CTX_start(ctx);
    if ((fac = BN_CTX_get(ctx)) == NULL)
        return -1;
    if ((random = BN_CTX_get(ctx)) == NULL)
        return -1;
    if ((vec_p = malloc_vector(p)) == NULL)
        return -1;

    if (BN_set_word(fac, 1) == (BN_ULONG)-1)
        return -1;

    for (i=0; i<vector->size; i++)
    {
        if (!BN_mul_word(fac, p-i))
            return -1;
    }

    size = BN_num_bytes(fac) + SECURITY_MARGIN_BYTES;

    if (gen_random_bn(seed, seed_len, random, size, fac, ctx))
        return -1;

    for (i=0; i<vec_p->size; i++) {
        vec_p->data[i] = i;
    }

    /* permute the last vector->size elements */
    for (i=p-1; i>=(p-1-vector->size); i--) {
        if ((rmndr = BN_div_word(random, i+1)) == (BN_ULONG)-1)
            return -1;
        tmp = vec_p->data[rmndr];
        vec_p->data[rmndr] = vec_p->data[i];
        vec_p->data[i] = tmp;
    }
    /* copy the permuted last vector->size elements */
    for (i=0; i<vector->size; i++)
        vector->data[i] = vec_p->data[vec_p->size-1-i];

    free_vector(vec_p);
    BN_CTX_end(ctx);

    return 0;
}

int bn2vector(BIGNUM *random, Vector* vector, long long p, long long offset)
{
    size_t i;
    BN_ULONG tmp;
    for (i=0; i<vector->size; i++) {
        if ((tmp = BN_div_word(random, p)) == (BN_ULONG)-1)
            return -1;
        vector->data[i] = tmp + offset;
    }
    return 0;
}

int gen_random_vector_bn(unsigned char *seed, size_t seed_len,
                         Vector* vector, int save_bn, BIGNUM *rnd,
                         long long p, long long offset, BN_CTX *ctx)
{
    BIGNUM *random, *p_exp, *bn_n, *bn_p;

	BN_CTX_start(ctx);
    if ((bn_p = BN_CTX_get(ctx)) == NULL){
        return -1;
    }
    BN_set_word(bn_p, p);

    if ((bn_n = BN_CTX_get(ctx)) == NULL)
        return -1;
    BN_set_word(bn_n, vector->size);

    if ((p_exp = BN_CTX_get(ctx)) == NULL)
        return -1;

    if (!BN_exp(p_exp, bn_p, bn_n, ctx)){
        handleErrors();
        return -1;
    }

    if (rnd == NULL){
        if ((random = BN_CTX_get(ctx)) == NULL)
            return -1;
        if (gen_random_bn(seed, seed_len, random, BN_num_bytes(p_exp), p_exp, ctx))
            return -1;
    } else {
        random = rnd;
    }

    if (save_bn){
        vector->bn = BN_dup(random);
        if (vector->bn == NULL)
            return -1;
    }
    if(bn2vector(random, vector, p, offset)){
        return -1;
    }

	BN_CTX_end(ctx);

    return 0;
}

int gen_random_vector_bn_batch(unsigned char *seed, size_t seed_len,
                               Vector **vectors, size_t nb_vectors, BN_CTX *ctx)
{
    BIGNUM *random, *p_exp, *bn_n, *bn_p;
    unsigned char *bytes;
    size_t size, i, j, total_size;
    BN_ULONG tmp;

	BN_CTX_start(ctx);
    if ((random = BN_CTX_get(ctx)) == NULL){
        return -1;
    }

    if ((bn_p = BN_CTX_get(ctx)) == NULL){
        return -1;
    }
    BN_set_word(bn_p, PKP_P);

    if ((bn_n = BN_CTX_get(ctx)) == NULL)
        return -1;
    BN_set_word(bn_n, vectors[0]->size);

    if ((p_exp = BN_CTX_get(ctx)) == NULL)
        return -1;

    if (!BN_exp(p_exp, bn_p, bn_n, ctx)){
        return -1;
    }

    size = BN_num_bytes(p_exp) + SECURITY_MARGIN_BYTES;

    total_size = size * nb_vectors;
    if ((bytes = malloc(total_size)) == NULL)
        return -1;

    if (SHAKE256(bytes, total_size, seed, seed_len))
        return -1;

    for (i=0; i<nb_vectors; i++){
        /* convert to BN */
        if (BN_bin2bn(bytes+i*size, size, random) == NULL) {
            fprintf(stderr, "Failed to convert random bytes to BN\n");
            return -1;
        }
        /* BN modular p exp n */
        if (!BN_nnmod(random, random, p_exp, ctx)) {
            fprintf(stderr, "Failed to calculate the modular of BN\n");
            return -1;
        }
        for (j=0; j<vectors[i]->size; j++) {
            tmp = BN_div_word(random, PKP_P);
            if (tmp == (BN_ULONG)-1)
                return -1;
            vectors[i]->data[j] = tmp;
        }
    }
    free(bytes);
	BN_CTX_end(ctx);
    return 0;
}

int vector2bn(Vector* vector, long long p, BIGNUM *random)
{
    size_t i;

    assert (random != NULL);
    BN_set_word(random, 0);

    for (i=0; i<vector->size; i++) {
        if (!BN_mul_word(random, p))
            return -1;
        if (!BN_add_word(random, vector->data[vector->size-1-i]))
            return -1;
    }

    return 0;
}

int inverse_permutation(Vector* v, Vector *inv_v)
{
    size_t i;
	if (inv_v->size != v->size)
		return -1;
    for (i=0; i<v->size; i++) {
        inv_v->data[v->data[i]] = i;
    }
    return 0;
}

/* p = pa*pb (apply first pb and then pa) */
Vector* permutation_mul(Vector* pa, Vector* pb)
{
    size_t i;
    Vector *p = malloc_vector(pa->size);
    if (p == NULL)
        return NULL;
    for (i=0; i<p->size; i++) {
        p->data[i] = pa->data[pb->data[i]];
    }
    return p;
}

Vector* permute_vector(Vector* v, Vector *p)
{
    size_t i;
    Vector *permuted;
    assert(v->size == p->size);

    permuted = malloc_vector(v->size);
    if (permuted == NULL)
        return NULL;

    for (i=0; i<v->size; i++) {
        permuted->data[i] = v->data[p->data[i]];
    }
    return permuted;
}
Vector* unpermute_vector(Vector* v, Vector *p)
{
	size_t i;
	Vector *permuted;
	assert(v->size == p->size);

	permuted = malloc_vector(v->size);
	if (permuted == NULL)
		return NULL;

	for (i = 0; i < v->size; i++) {
		permuted->data[p->data[i]] = v->data[i];
	}
	return permuted;
}


/* matrix's column j is the colunm indicated by p[j] */
Matrix* permute_matrix(Matrix* m, Vector *p)
{
    size_t i,j;
    Matrix *permuted = malloc_matrix(m->row, m->column);
    if (permuted == NULL)
        return NULL;
    for (j=0; j<m->column; j++) {
        for (i=0; i<m->row; i++) {
            permuted->data[i][j] = m->data[i][p->data[j]];
        }
    }
    return permuted;
}

int init_matrix_id_random(Matrix* m, long long p, unsigned char *seed,
                          size_t seed_len, BN_CTX *ctx)
{
    size_t i,j;
    Vector **helper;
    if ((helper = malloc(m->row*sizeof(Vector*))) == NULL)
        return -1;

    /* identity matrix(m, m) */
    for (i=0; i<m->row; i++) {
        m->data[i][i] = 1;
        if ((helper[i] = malloc_vector(m->column-m->row-1)) == NULL)
            return -1;
    }
    if (gen_random_vector_bn_batch(seed, seed_len, helper, m->row, ctx))
        return -1;
    /* random matrx(m, n-m-1) */
    for (i=0; i<m->row; i++) {
        for (j=m->row; j<m->column-1; j++) {
            m->data[i][j] = helper[i]->data[j-m->row];
        }
        free_vector(helper[i]);
    }
    free(helper);
	return 0;
}

/* Generate matrix m and its kernel vector v, m*v = 0  */
int init_kern_vector(Matrix* m, Vector* v, long long p, BN_CTX *ctx)
{
    size_t i,j;
    long long tmp;
	long long inv;
	inv = mod_mul_inverse(v->data[m->column - 1], p, ctx);
    for (i=0; i<m->row; i++) {
        tmp = v->data[i];
        for (j=m->row; j<m->column-1; j++) {
            tmp += m->data[i][j]*v->data[j];
        }
        m->data[i][j] = mod(mod(0-tmp, p)*inv, p);
    }
    return 0;
}

int factorial(BN_ULONG n, BIGNUM *fac)
{
    if (BN_set_word(fac, 1) == (BN_ULONG)-1)
        return -1;
    while (n > 0){
        if (!BN_mul_word(fac, n))
            return -1;
        n--;
    }
    return 0;
}

void personalize_msg(unsigned char *m, size_t mlen,
             unsigned char *personalization_string, size_t size)
{
    size_t i;
    for (i=0; i<mlen; i++)
        m[i] ^= personalization_string[i%size];
}

int SHAKE256(unsigned char *output, size_t outputByteLen,
             unsigned char *input, size_t inputByteLen)
{
    EVP_MD_CTX *shake256_ctx;
    if ((shake256_ctx =EVP_MD_CTX_new()) == NULL){
        handleErrors();
        return -1;
    }
    if (EVP_DigestInit_ex(shake256_ctx, EVP_shake256(), NULL) != 1) {
        handleErrors();
        return -1;
    }
    if (EVP_DigestUpdate(shake256_ctx, input, inputByteLen) != 1) {
        handleErrors();
        return -1;
    }
    if (EVP_DigestFinalXOF(shake256_ctx, output, outputByteLen) != 1) {
        handleErrors();
        return -1;
    }
    EVP_MD_CTX_free(shake256_ctx);
	return 0;
}
#ifdef DEBUG
void dump_mem(char * msg, unsigned char * mem, int index, int len)
{
	FILE *f;
	int i;
	if ((index > 10) && (index < 155)) return;
	f = fopen("logs.txt", "a");
	if (index >= 0) {
		fprintf(f, "%s [%d] _ %d\n", msg, index, len);
	}
	else {
		fprintf(f, "%s _ %d\n", msg, len);
	}
	for (i = 0; i < len; i++)
	{
		fprintf(f, "%02x", mem[i]);
		if (i % 32 == 31)
		{
			fprintf(f, "\n");
		}
	}
	fprintf(f, "\n");
	fclose(f);
}

void dump_vector(char * msg, Vector * v, int index)
{
	FILE *f;
	int i;
	if ((index > 10) && (index < 155)) return;
	f = fopen("logs.txt", "a");
	if (index >= 0) {
		fprintf(f, "%s [%d] _ %d\n", msg, index, v->size);
	}
	else {
		fprintf(f, "%s _ %d\n", msg, v->size);
	}
	for (i = 0; i < v->size; i++)
	{
		fprintf(f, "%03d ", v->data[i]);
		if (i % 16 == 15)
		{
			fprintf(f, "\n");
		}
	}
	fprintf(f, "\n");
	fclose(f);
}
#endif

#ifdef __linux__
/* https://github.com/IAIK/flush_flush/blob/master/cacheutils.h */
uint64_t rdtsc_begin() {
  uint64_t a, d;
  __asm__ volatile ("mfence\n\t"
    "CPUID\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}

uint64_t rdtsc_end() {
  uint64_t a, d;
  __asm__ volatile("mfence\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "CPUID\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}
#else /* __linux__ */
#ifdef _WIN32
uint64_t rdtsc_begin()
{
    unsigned __int64 i;
    unsigned int ui;
	int cpuInfo[4];

	__faststorefence();
    __cpuid(cpuInfo, 0);
    i = __rdtscp(&ui);
	__faststorefence();
	return i;
}

uint64_t rdtsc_end()
{
	unsigned __int64 i;
    unsigned int ui;
	int cpuInfo[4];

	__faststorefence();
    i = __rdtscp(&ui);
    __cpuid(cpuInfo, 0);
	__faststorefence();
	return i;
}

#else /* _WIN32 */
    #error Only linux and windows builds are supported.
#endif /* _WIN32 */
#endif /* __linux__ */
