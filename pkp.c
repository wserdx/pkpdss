#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kat.h"
#include "sig_api.h"

extern void perf_eval();

int main()
{
    perf_eval();
//    generate_kat_files();
	getchar();
	return 0;
}
