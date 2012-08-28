#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stdint.h>

#include "md5.h"


// Mersenne Twister parameters -- stripped from the PHP source
#define N             (624)                /* length of state vector */
#define M             (397)                /* a period parameter */
#define hiBit(u)      ((u) & 0x80000000U)  /* mask all but highest   bit of u */
#define loBit(u)      ((u) & 0x00000001U)  /* mask all but lowest    bit of u */
#define loBits(u)     ((u) & 0x7FFFFFFFU)  /* mask     the highest   bit of u */
#define mixBits(u, v) (hiBit(u)|loBits(v)) /* move hi bit of u to hi bit of v */

#define twist(m,u,v)  (m ^ (mixBits(u,v)>>1) ^ ((uint32_t)(-(uint32_t)(loBit(u))) & 0x9908b0dfU))

#define MD5_LEN 16

#define MTOFFSET 4

static inline
void php_mt_initialize(uint32_t seed, uint32_t *state)
{
  register uint32_t *s = state;
  register uint32_t *r = state;
  register int i = 1;
  
  *s++ = seed & 0xffffffffU;
  for( ; i < N-200; ++i ) {
    *s++ = ( 1812433253U * ( *r ^ (*r >> 30) ) + i ) & 0xffffffffU;
    r++;		
  }
}


static inline 
uint32_t temper(uint32_t y)
{	
  y ^= (y >> 11);
  y ^= (y <<  7) & 0x9d2c5680U;
  y ^= (y << 15) & 0xefc60000U;
  y ^= (y >> 18) ;
  return y;
}

#define OFFSET 4 //12 for real installations

static inline size_t
hexConvert(char buf[], unsigned int n1, unsigned int n2)
{
  static char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  char *ptr, *end;
  unsigned long value, len = 0;
  
  end = ptr = buf + 32 - 1;
  *ptr = '\0';
	
  value = n2;
  do {
    *--ptr = digits[value % 16];
    value /= 16;
    len ++;
  } while (ptr > buf && value);

  value = n1;
  do {
    *--ptr = digits[value % 16];
    value /= 16;
    len ++;
  } while (ptr > buf && value);

  
  strcpy(buf, ptr);
  return len;
}



char *
mediawikiHash(unsigned int seed, char hash[])
{
  MD5_CTX md5;
  uint32_t r1, r2;
  uint32_t state[N];
  uint32_t *p;
  char buf[32];
  int len;

  php_mt_initialize(seed, state);
  p = state;

  r1 = temper(twist(p[M+OFFSET], p[0+OFFSET], p[1+OFFSET])) >> 1;
  r2 = temper(twist(p[M+OFFSET+1], p[0+OFFSET+1], p[1+OFFSET+1])) >> 1;
  
  len = hexConvert(buf, r1, r2);  

  MD5_Init( &md5 );
  MD5_Update( &md5, buf, len);
  MD5_Final( hash, &md5 );
  return hash;
}

typedef struct {
  char *hashName;
  char *(*hashFunc)(unsigned int, char *);
  unsigned int hashLen;
} hashFuncEntry;



hashFuncEntry hashFuncArray[] = { // this symbol will be exported.
  {"wikihash",     mediawikiHash,    16},
  {0,         0,      0},        // terminated by a zero entry.
};


#ifdef __STANDALONE__

static
char *readable(char *data)
{
  char r[33];
  int i;
  char *encoded = r;

  for (i = 0; i < 16; i ++, encoded += 2, data ++)
    sprintf(encoded, "%02hhx", *data);
  *encoded = '\0';
  return strdup(r);
}


//test main, not to be used
int main(int argc, char *argv[])
{
  int i;
  char buf[MD5_LEN];

  mediawikiHash(atoi(argv[1]), buf);
  
  printf("%s\n", readable(buf));
  return;
}

#endif
