/**
   This file contains a lightweight rainbow tables implementation for
   generating randomness exploits against PHP applications. For more
   info check the paper:
   "I Forgot Your Password: Randomness Attacks Against PHP applications"

   By lightweight we mean that the tables must be small enough to fit
   in the memory of the system. Since the targeted genereators have a 
   32 bit seed, we only need to have tables for a 2^{32} search space.
   
   Some sample parameters for the table reveal that we could easily 
   have near 100% success rate with tables that will easily fit in
   the memory of any modern system:

   For example:
   Chain Number | Chain length | no. of tables | Success Probality 
   
       10m           1000             3             0.990317
       10m           3000             3             0.999879
       5m            3000             3             0.997676
       
   Notice that each chain entry is 64 bit so we can create a 10m entries
   table using about 80mb of memory.

 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h> 
#include <libgen.h>

#include "rand.h"

#define WORKER_BUFFER_SIZE 8192

#define MAX_HASH_SIZE 64

#define HASHLIB "hashlib"
#define HASHARRAY "hashFuncArray"

#define MAX_FUNC_NAME 64

#define MAX_HASHLIBS 10

#define MAX_SEED 0xffffffff

typedef unsigned int chainEntry;

typedef char *(*hashFuncPtr)(unsigned int, char *);

typedef struct {
  chainEntry startpoint;
  chainEntry endpoint;
} chain;


typedef struct { 
  unsigned int chainNum;
  unsigned int chainLen;
  unsigned int hashLen;  
  char *(*hash)(unsigned int, char *);
  FILE * tableFilePtr;
} workerData;

static pthread_mutex_t mutex  = PTHREAD_MUTEX_INITIALIZER;


typedef struct {
  char *hashName;
  char *(*hashFunc)(unsigned int, char *);
  unsigned int hashLen;
} hashFuncEntry;


////////////////////////////////////////////////////////////////////////
/// Help functions


/*
 * Reduction function. Takes as input a hash and reduces it to a 32 bit 
 * unsigned integer.
 */
chainEntry 
reduce(char *hash, unsigned int hashLen, unsigned int round)
{
  chainEntry reduced = 0;
  chainEntry *hashInt = (chainEntry *) hash;
  unsigned int i = 0;

  // XOR is very fast so we will quickly consume most of the hash
  for (i = 0; i < hashLen / sizeof(chainEntry); i ++, hashInt ++)
    reduced ^= *hashInt;
  
  // Make an addition of the remaining hash bytes to the reduced value
  for (i = 0; i < hashLen % sizeof(chainEntry); i++)
    reduced += (chainEntry) hash[hashLen - 1 - i];

  return reduced^round;
}

/*
 * Generates an appropriate table name for the given table parameters.
 */

char *generateTableName(char *hashName, unsigned int chainNum, 
			unsigned int chainLen, unsigned int index)
{
  char buffer[512];

  snprintf(buffer, 512, "%s.%u.%u.%u.rt", hashName, chainNum, chainLen, index);
  return strdup(buffer);
} 

/*
 * Does a linear search for all files named hashlib[0-9].so. In each such
 * file found will attempt to resolve the function named hashFuncName. It
 * will return a pointer to that function along with the length of the 
 * hash stored in the integer pointed by the hashLen pointer
 */

hashFuncPtr
resolveHashFunc(char *hashFuncName, unsigned int *hashLen)
{
  int i;
  char libname[32];
  void *handle;

  hashFuncEntry *hf;

  for (i = 0; i < MAX_HASHLIBS; i ++) {
    snprintf(libname, 32, "./%s%d.so", HASHLIB, i);
    
    handle = dlopen(libname, RTLD_LAZY);
    if (handle == NULL)
      continue;

    
    hf = (hashFuncEntry *) dlsym(handle, HASHARRAY);
    if (hf == NULL) {
      dlclose(handle);
      continue;
    }
    
    // Iterate all entries in the hashFuncEntry array 
    while (hf->hashName != NULL) {
      
      if (!strcmp(hf->hashName, hashFuncName)) {
	*hashLen = hf -> hashLen;	
	return hf->hashFunc;
      }      
      hf ++;
    } 
    
    dlclose(handle);
  }


  return NULL;
}


///////////////////////////////////////////////////////////////////////////
/// Functions that implement the generation of rainbow tables.

/*
 * Generates a chain if length chainLen using the function hash. * 
 */
static inline chain 
generateChain(char *(*hash)(unsigned int, char *), unsigned int chainLen, 
	      unsigned int hashLen)
{
  unsigned int i = 0;
  chain result;
  chainEntry tmp;
  char buf[MAX_HASH_SIZE];

  result.startpoint = tmp = rand_cmwc_r();
  
  for (; i < chainLen; i ++)
    tmp = reduce(hash(tmp, buf), hashLen, i);
  
  result.endpoint = tmp;
  return result;
}


/*
 * This is the worker function of each thread. Will generate a number of chains
 * depending on the total chains and the total threads and will write the into the
 * output table in buckets of WORKER_BUFFER_SIZE to improve performanace.
 */
static void *
chainGenerationWorker(void *arg)
{
  workerData *data = (workerData *) arg;
  unsigned int i, j, chainsLeft;
  chain buffer[WORKER_BUFFER_SIZE];

  
  // Make chains in buckets of WORKER_BUFFER_SIZE and write them to the file
  for (i = 0; i < data->chainNum / WORKER_BUFFER_SIZE + 1; i ++) {
    chainsLeft = (i < data->chainNum / WORKER_BUFFER_SIZE)? WORKER_BUFFER_SIZE 
      : data->chainNum % WORKER_BUFFER_SIZE;
    for (j = 0; j < chainsLeft; j ++)
      buffer[j] = generateChain(data->hash, data->chainLen, data->hashLen); //check for errors?

    pthread_mutex_lock(&mutex);
    if (fwrite(buffer, sizeof(chain), chainsLeft, data->tableFilePtr) 
	!= chainsLeft) {
      fprintf(stderr, "Error writing data to file.");
      pthread_mutex_unlock(&mutex);
      return (void *)-1;
    }
    pthread_mutex_unlock(&mutex);
    
  }
  
  return (void *)0;
}


/*
 * Spawns the necessary threads in order to create the rainbow table and in addition
 * does some bookkeeping.
 */
int createRainbowTable(unsigned int chainNum, unsigned int chainLen,
		       char *(*hash)(unsigned int, char *), 
		       unsigned int hashLen,
		       char *tableName)
{  
  FILE *tablePtr = fopen(tableName, "w");
    
  if (tablePtr == NULL)
    return -1;
  
  // thread number is the number of online processors in the system.
  unsigned int threadNum;
  long conf =  sysconf(_SC_NPROCESSORS_ONLN);
  if (conf <= 0)
    threadNum = 1;
  else
    threadNum = conf;        
  

  int i;
  pthread_t *tid = malloc(threadNum * sizeof(pthread_t));
  workerData *args = malloc(threadNum * sizeof(workerData));

  if (tid == NULL) 
    return -1;

  if (args == NULL) {
    free(tid);
    return -1;
  }

  // generate worker threads.
  for (i = 0; i < threadNum; i ++) {
    args[i].chainNum = (i < threadNum - 1)?
      chainNum / threadNum : chainNum / threadNum + chainNum % threadNum;
    args[i].chainLen = chainLen;
    args[i].hash = hash;
    args[i].hashLen = hashLen;
    args[i].tableFilePtr = tablePtr;
          
    pthread_create(&tid[i], NULL, chainGenerationWorker, (void *)&args[i]);        
  }
  
  void *ret;
  int status = 0;
  // on success threads will return 0. If a non zero value is returned 
  // an error occured.
  for (i = 0; i < threadNum; i ++) {
    pthread_join(tid[i], &ret);  
    status |= (int)ret;
  }
  
  free(tid);
  free(args);
  fclose(tablePtr);
  if (status)
    return -1;
  return 1;
}


void inline 
swap(chain *a, chain *b)
{
  chain t=*a; *a=*b; *b=t;
}


/*
  Sort the rainbow table using quicksort.
 */
void 
quickSortTable(chain *table, unsigned int beg, unsigned int end)
{

  if (end > beg + 1) {

    int piv = table[beg].endpoint, l = beg+1, r = end;
    while (l < r) {
      if (table[l].endpoint <= piv)
	l++;
      else
	swap(&table[l], &table[--r]);
    }
    swap(&table[--l], &table[beg]);
    quickSortTable(table, beg, l);
    quickSortTable(table, r, end);
  }

}


/*
 * Sort a rainbow table and store the results in the same file.
 */
int 
sortRainbowTable(char *tableName, unsigned int chainNum)
{
  struct stat sb;
  chain *table;
  int fd = open(tableName, O_RDWR);

  if (fd < 0) {
    return -1;
  }
  
  if (fstat (fd, &sb) == -1) {
    perror ("fstat");
    return -1;
  }
  
  
  table = (chain *) mmap (0, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (table == MAP_FAILED) {
    perror ("mmap");
    return 1;
  }

  quickSortTable(table, 0, chainNum);

  close(fd);
  munmap(table, sb.st_size);
  return 1; 
}



/*
 * Top level function that generates a rainbow table. It will resolve the hash
 * function and create an appropriate table name before calling the internal
 * table generation function and afterwards the table sorting function.
 */
int
generateRainbowTable(unsigned int chainNum, unsigned int chainLen, 
		     unsigned int index, char *hashName)
  
{
  
  unsigned int hashLen;
  char *(*hashFunc)(unsigned int, char *) = resolveHashFunc(hashName, &hashLen);
  
  if (hashFunc == NULL)
     return -1;


  char *tableName = generateTableName(hashName, chainNum, chainLen, index);
  
  if (createRainbowTable(chainNum, chainLen, hashFunc, hashLen,
			 tableName) < 0 || 
      sortRainbowTable(tableName, chainNum) < 0)
    return -1;

  free(tableName);
  return 1;
}



/////////////////////////////////////////////////////////////////////////////

/*
 * Search the table array for a given endpoint using binary search.
 * When a match is found, it traverses the array backwards to find
 * the first occurence of this match and returns a pointer in that
 * position. This way all other occurences can be enumerated efficiently
 * by scanning the array linearly in increasing order.
 */

int 
searchTable(chain *table, int chainNum, chainEntry endpoint, 
	    chainEntry *index)
{
  unsigned int beg = 0, end = chainNum - 1;

  while (beg  < end) {
    long mid = (beg + end) / 2;

    if (endpoint < table[mid].endpoint)
      end = mid;
    else if (endpoint > table[mid].endpoint)
      beg = mid + 1;
    else {
      while (mid >= 0 && endpoint == table[mid--].endpoint);
      *index = (mid < 0)? 0 : mid + 1;
      return 1;    
    }
  }
  return 0;    
}

/*
 * When a candidate match is found in an endpoint this function
 * regenerates the chain to either obtain the seed or to report
 * that the match was a false positive.
 */

int regenerateChain(chainEntry startpoint, unsigned int chainLen, 
		    char *(*hashFunc)(unsigned int, char *), 
		    unsigned int hashLen,
		    char *targetHash, unsigned int *seed)
{
  int i;
  chainEntry tmp = startpoint;
  char buf[MAX_HASH_SIZE];
  
  for (i = 0; i < chainLen; i ++) {
    if (!memcmp(hashFunc(tmp, buf), targetHash, hashLen)) {
      *seed = tmp;
      return 1;
    }
    tmp = reduce(buf, hashLen, i);
  }
  
  return 0;
}

int 
searchHashInMemory(chain *table, unsigned int chainNum, unsigned int chainLen,
		   char *(*hashFunc)(unsigned int, char *), 
		   unsigned int hashLen,
		   char *targetHash, unsigned int *seed)
{

  int i, j;
  char buf[MAX_HASH_SIZE];
  chainEntry index, r;

  for (j = chainLen - 1; j >= 0; j --) {
    char *tmpHash =  targetHash;
    for (i = j; i < chainLen-1; i ++) {
      r = reduce(tmpHash, hashLen, i);
      tmpHash = hashFunc(r, buf);
    }    
  
    // A note on the search algorithm:
    // Because we dont keep only unique endpoints, in each match we have
    // a number of startpoints that we can try to regenerate in order to
    // find the target seed. The searchTable function will return a pointer
    // to the first such entry and then we can check them all linearly.
    // This makes a nice improvements on the number of hashes that we
    // actually find.
    r = reduce(tmpHash, hashLen, i);
    if (searchTable(table, chainNum, r, &index)) 
      do { 
	if (regenerateChain(table[index++].startpoint, chainLen, hashFunc, 
			    hashLen, targetHash, seed))
	  return 1;	  
      } while (table[index].endpoint == r);
    

  }
  return 0;
}
		   

int parseTablename(char *tablename, char *hashFuncName, unsigned int *chainNum, 
		   unsigned int *chainLen)
{
  char *copyTablename = strdup(tablename); //FIXME: memory leak
  char *tableBasename = basename(copyTablename);
  char *dotPos;
  unsigned int index;


  dotPos = strchr(tableBasename, '.');
  if (dotPos == NULL)
    return -1;

  *dotPos = ' '; // hack to make sscanf parse the filename correctly
  sscanf(tableBasename, "%s %u.%u.%u.rt", hashFuncName, chainNum, chainLen, &index);
  *dotPos = '.';

  return 1;
}

/*
 * makes all the necessary actions to parse and search the rainbow table 
 * pointed by tableName. If a correct seed is found then a positive value
 * is returned and the seed is stored in the integer pointed by the 
 * seed pointer.
 */
int 
searchRainbowTable(char *tableName, char *targetHash, unsigned int *seed)
{
  
  char hashFuncName[MAX_FUNC_NAME];
  unsigned int chainNum, chainLen, hashLen;
  
  // Parse the table name to extract the table information
  if (parseTablename(tableName, hashFuncName, &chainNum, &chainLen) < 0)
    return -1;

  // Obtain a pointer to the hash function
  char *(*hashFunc)(unsigned int, char *) = resolveHashFunc(hashFuncName, 
							    &hashLen);
  if (hashFunc == NULL)
    return -1;


  struct stat sb;
  int fd = open(tableName, O_RDONLY);
  if (fd < 0)
    return -1;


  if (fstat (fd, &sb) < 0) {   
    return -1;
  }
  
  // We directly mmap the table in memory. Since the tables are small
  // this give us an easy way to work directly with an array rather
  // than getting into complex and costly file operations.
  chain *table = (chain *) mmap (0, sb.st_size, 
				 PROT_READ, MAP_SHARED, fd, 0);
  if (table == MAP_FAILED) {
    perror ("mmap");
    return -1;
  }
  
  // Search the array of the table for the target hash.
  int found = searchHashInMemory(table, chainNum, chainLen, 
				 hashFunc, hashLen,
				 targetHash, seed);
  
  
  close(fd);
  munmap(table, sb.st_size);
  return found;
}


///////////////////////////////////////////////////////////////////////////////
// Functions that implement the exhaustive search cracker. 



typedef struct {
  char *hash;
  unsigned int hashLen;
  unsigned int start,end;
  unsigned int *seed;
  unsigned short int *found;
  char *(*hashFunc)(unsigned int, char *);
} WorkerOptions;



/*
 * A thread worker. Searches a given range for the supplied hash value
 * and halts when that value is found or the range is exhausted.
 */
void *
seedRecoveryWorker(void *arg)
{
  WorkerOptions *opt = (WorkerOptions *) arg;
  char nh[opt->hashLen];
  unsigned int i; 
  
  for (i = opt->start; i <= opt->end; i++) {   
    if (!memcmp(opt->hash, opt->hashFunc(i, nh), opt->hashLen)) {
      *(opt->found) = 1;
      *(opt->seed) = i;
    }
    
    if (*(opt->found))
      break;
  }    
  return NULL;
}



int 
searchHashOnline(char *hashFuncName, char *targetHash,  
		 unsigned int *seed)
{
 
  unsigned int start = 0, end = MAX_SEED;
  unsigned short int found = 0;
  unsigned int threads, i, hashLen;
  long conf =  sysconf(_SC_NPROCESSORS_ONLN);
  
  // Thread number is set to the number of active processors on the system
  if (conf <= 0)
    threads = 1;
  else
    threads = conf;        
  
  pthread_t *tid = (pthread_t *) malloc(threads * sizeof(pthread_t));
  WorkerOptions *opt = (WorkerOptions *) malloc(threads * sizeof(WorkerOptions));    
  unsigned int range = MAX_SEED / threads;
  char *(*hashFunc)(unsigned int, char *);

  hashFunc = resolveHashFunc(hashFuncName, &hashLen);
  if (hashFunc == NULL)
    return 0;

  //create threads...
  for (i = 0; i < threads; i ++) {   
    opt[i].start = start;
    opt[i].end = (i == threads - 1)? end : (start + range);
    opt[i].found = &found;
    opt[i].hashLen = hashLen;
    opt[i].seed = seed;
    opt[i].hash = targetHash;
    opt[i].hashFunc = hashFunc;

    pthread_create(&tid[i], NULL, seedRecoveryWorker, (void *)&opt[i]);    

    start += range;
  }
  
  for (i = 0; i < threads; i ++)
    pthread_join(tid[i], NULL);

  free(opt);
  free(tid);

  return found;
}


/////////////////////////////////////////////////////////////////////////
// Main function used by the standalone version of the tool

#ifndef __CRACK_LIB__

#define GENERATE_HASH_TABLES "generate"
#define SEARCH_HASH_TABLES "search"
#define CRACK_HASH "crack"

void
bytesFromHash(char bytes[], char *hash)
{
  char num[3];
  unsigned int hexnum;
  int i,j;

  memset(bytes, '\0', MAX_HASH_SIZE);
  memset(num, '\0', 3);
  for (i = j = 0; i < 32; i += 2){
    num[0] = hash[i];
    num[1] = hash[i + 1];
    sscanf(num,"%x",&hexnum);
    bytes[j++] = hexnum;
  } 
  return;
}

void usage() 
{
  fprintf(stderr,
	  "snowflake: hash cracking utility.\n"
	  "Usage: snowflake [mode] [options]\n"
	  "Modes:\n"
	  "\t generate <chain num> <chain len> <table num> <hash function>\n"
	  "\t search <rainbow table> <target hash>\n"
	  "\t crack  <hash function> <target hash>\n\n");
}


int main(int argc, char *argv[])
{
  unsigned int seed;
  int found = 0;
  char bytes[MAX_HASH_SIZE];

  if (argc < 2) {
    usage();
    return 0;
  }
  
  if (!strcmp(GENERATE_HASH_TABLES, argv[1])) {
    if (argc != 6) 
      goto invalid_args;
    unsigned int i, tnum = atoi(argv[4]);
    for (i = 0; i < tnum; i ++)
      generateRainbowTable(atoi(argv[2]), atoi(argv[3]), i, argv[5]);
    return 0;
  } else if (!strcmp(SEARCH_HASH_TABLES, argv[1])) {
    if (argc != 4) 
      goto invalid_args;
    bytesFromHash(bytes, argv[3]);
    found = searchRainbowTable(argv[2], bytes, &seed);
  } else if (!strcmp(argv[1], CRACK_HASH)){
    if (argc != 4)
      goto invalid_args;
    bytesFromHash(bytes, argv[3]);
    found = searchHashOnline(argv[2], bytes, &seed);
  } else {
    usage();
    fprintf(stderr, "\n[-] Invalid mode of operation.\n");
    return 1;
  }

  if (found > 0)
    fprintf(stdout, "[+] Seed found: %u\n", seed);
  else if (!found)
    fprintf(stdout, "[-] Seed not found :-(\n");
  else
    fprintf(stderr, "[-] An error occured.\n");

  return 0;
  invalid_args:
  usage();
  fprintf(stderr, "\n[-] Invalid number of arguments\n");
  return 1;
}

#endif
