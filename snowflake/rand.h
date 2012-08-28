#ifndef __RAND_CMWC__
#define __RAND_CMWC__

#include <stdint.h>

void srand_cmwc(uint32_t);
uint32_t rand_cmwc(void);
uint32_t rand_cmwc_r(void);

#endif
