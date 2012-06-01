#include <stdio.h>
#include <stdlib.h>

#include "sysdep.h"
#include "calc_times_proc.h"

#define NOMBRE_BOUCLE 10000000
#define OPERATION_PER_LOOP 4

//#define DEBUG

int start_benchmark(float *flop_per_sec)
{
  init_cputime();
  long long int times[3];
  long long int result;
  pid_t pid = getpid();
#if defined(DEBUG)
  printf("Starting benchmark for %d\n", pid);
#endif
  if(!ask_time(pid, times))
  {
    long long int initialTime = times[1]+times[2];
    int i;
    float a, b, c;
    for(i=NOMBRE_BOUCLE; i>=0; --i)
    {
      b=(float)(a*c);
      b=(float)(a+c);
      b=(float)(a-c);
      b=(float)(a/c);
    }
    ask_time(pid, times);
    result = (times[1] + times[2])-initialTime;
#if defined(DEBUG)
    printf("Duration of benchmark : %lld\n", result);
#endif
    float time_for_flop = ((float)result)/(NOMBRE_BOUCLE*OPERATION_PER_LOOP);
    *flop_per_sec = (1000000.)/time_for_flop;

    printf("Result for benchmark : %f -> (%f flops)\n", time_for_flop, *flop_per_sec);
  
  }
  else
  {
#if defined(DEBUG)
    printf("Unable to have system time\n");
#endif
    return -1;
  }
  
  
  finish_cputime();
  
  return EXIT_SUCCESS;
}