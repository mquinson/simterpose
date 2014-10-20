/* pthread -- A program that spawns threads                                  */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

static void *hello(void *arg)
{

  int *id = (int *) arg;
  fprintf(stderr, "child %d: hello world \n", *id);
  pthread_exit(NULL);

}

int main()
{

  pthread_t threads[3];
  int id[3] = { 1, 2, 3 };
  int i;
  int n = 10;

  for (i = 0; i < n; i++) {
    fprintf(stderr, "Create thread %d\n", i + 1);
    pthread_create(&threads[i], NULL, hello, (void *) &id[i]);
  }
  for (i = 0; i < n; i++) {
    pthread_join(threads[i], NULL);
  }
  pthread_exit(NULL);


}
