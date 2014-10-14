#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include <sys/unistd.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <sched.h>
#include <stdlib.h>

void *thr(void *t)
{
  int i = 1000000000;

  fprintf(stderr,"User thread %lu\n",pthread_self());
  while(i)
    i--;
  return(NULL);
}

int main(int argc, char **argv)
{  

  pthread_t t1, t2;

//  start_timer(100);
  assert(pthread_create(&t1,NULL,thr,NULL) == 0);
  assert(pthread_create(&t2,NULL,thr,NULL) == 0);
  thr(NULL);

  exit(0);
}
