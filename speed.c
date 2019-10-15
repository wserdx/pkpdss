#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "kat.h"
#include "sig_api.h"
#include "pkp_utils.h"
#include "rng.h"

#define NTESTS 1000
#define MLEN 32

/* same performace test with MQDSS */

static int cmp_llu(const void *a, const void*b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2) return l[llen / 2];
    else return (l[llen/2 - 1] + l[llen/2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc=0;
    size_t i;
    for(i = 0; i < tlen; i++) {
        acc += t[i];
    }
    return acc/(tlen);
}

static void print_results(const char *s, unsigned long long *t, size_t tlen, int mult)
{
  printf("%s", s);

  printf("\n");
  printf("median        : %llu\n", median(t, tlen));
  printf("average       : %llu\n", average(t, tlen));
  if (mult > 1) {
    printf("median  (%3dx): %llu\n", mult, mult*median(t, tlen));
    printf("average (%3dx): %llu\n", mult, mult*average(t, tlen));
  }
  printf("\n");
}

int perf_eval()
{
    unsigned long long t[4][NTESTS];

    unsigned char *pk = malloc(SIG_PUBLICKEYBYTES);
    unsigned char *sk = malloc(SIG_SECRETKEYBYTES);
    uint64_t start, end;

    unsigned char m[MLEN];
    unsigned char *sm;
    unsigned long long smlen;
    unsigned char *seed;

    sm = (unsigned char *)calloc(SIG_BYTES, sizeof(unsigned char));

    int i;

    printf("-- Performance over %d executions of keygen, sign, verf on %d bytes messages --\n\n",
        NTESTS, MLEN);

    if ((seed = malloc(RNG_SEED_SIZE)) == NULL)
        return -1;
    for(i=0; i<NTESTS; i++) {
        sysrandom(m, MLEN);
#ifdef DEBUG
		memset(m, 0, MLEN);
#endif

        if (sysrandom(seed, RNG_SEED_SIZE) == -1) {
            fprintf(stderr, "ERROR: sysrandom(seed)\n");
            return -1;
        };
        randombytes_init(seed, NULL);
        start = rdtsc_begin();
        if (sig_keygen(pk, sk)) {
            fprintf(stderr, "Failed to generate keys\n");
            return -1;
        }
        end = rdtsc_end();
        t[0][i] = end - start;


        start = rdtsc_begin();
        if (sig_sign(sk, m, MLEN, sm, &smlen)) {
            fprintf(stderr, "Failed to sign\n");
            return -1;
        }
        end = rdtsc_end();
        t[1][i] = end - start;


        start = rdtsc_begin();
        if (sig_verf(pk, sm, smlen, m, MLEN)) {
            fprintf(stderr, "Failed to verify signed message\n");
            return -1;
        }
#ifdef DEBUG
		return 0;
#endif
		end = rdtsc_end();
        t[2][i] = end - start;

        t[3][i] = smlen;

    }
    print_results("sig_keygen: ", t[0], NTESTS, 1);
    print_results("sig_sign: ", t[1], NTESTS, 1);
    print_results("sig_verf: ", t[2], NTESTS, 1);
    print_results("signature size: ", t[3], NTESTS, 1);

    free(seed);
    free(sm);
    free(pk);
    free(sk);
    return 0;
}
