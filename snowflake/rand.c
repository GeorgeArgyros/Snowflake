/**
   This implementation is based on the code taken from the Wikipedia article 
   on multiply with  carry generators:
   (http://en.wikipedia.org/wiki/Multiply-with-carry).
	
   Author: George Argyros (argyros.george@gmail.com)

   This generator is very fast with a huge period and satisfying randomness
   properties.
 */
#include <sys/time.h> 

#include <pthread.h>

#include "rand.h"

#define PHI 0x9e3779b9
 
static uint32_t Q[4096], c = 362436, seeded = 0;
 
static pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;

void srand_cmwc(uint32_t x)
{
        int i;
 
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
 
        for (i = 3; i < 4096; i++)
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
 
static void custom_seed()
{
  struct timeval tv;

  gettimeofday(&tv, 0);

  srand_cmwc(tv.tv_sec ^ tv.tv_usec);
  seeded = 1;
}



uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;

	if (!seeded)
	  custom_seed();


        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}


uint32_t rand_cmwc_r()
{
  uint32_t r;

  pthread_mutex_lock(&mutex);
  r = rand_cmwc();
  pthread_mutex_unlock(&mutex);
  return r;
}
