/* lib_time - Handles the functions about time */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.            */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU LGPLv2) which comes with this package. */

#define _GNU_SOURCE

#include <simgrid/msg.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/timeb.h>
#include <unistd.h>
#include <math.h>

/* Function allowing to log every wrapped functions */
void LogWrap(char *mess){
  FILE *file_log = fopen("../file_log", "a");
  fprintf(file_log, "%s", mess);
  fclose(file_log);
}

/* TODO: All functions are not implemented */
/* Wrapper of time functions */
int ftime(struct timeb *tp){
  LogWrap("ftime call\n");
  double sec = MSG_get_clock();
  tp->time = floor(sec);
  tp->millitm = (sec - floor(sec)) * 1000;
  tp->timezone = 0;
  tp->dstflag = 0;
  LogWrap("ftime call done \n");
  return 0;
}

time_t time(time_t *t){
  LogWrap("time call\n");
  double sec = MSG_get_clock();
  if ( t != NULL)
    *t = (time_t) sec;
  LogWrap("time call done \n");  
  return (time_t) sec;    
}

int gettimeofday(struct timeval *restrict tp, void *restrict tzp){
  LogWrap("gettimeofday call\n");
  printf("This function is obsolescent, call clock_gettime()\n");
  LogWrap("gettimeofday done call\n");
}

struct tm * localtime(const time_t *timep){
  printf("[%d] [localtime] Unhandled function\n",getpid());
  return NULL;
}

time_t mktime(struct tm *tm){
  printf("[%d] [mktime] Unhandled function\n",getpid());
  return 0;
}

int clock_getres(clockid_t clk_id, struct timespec *res){
  printf("[%d] [clock_getres] Unhandled function\n",getpid());
  return 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp){
  LogWrap("clock_gettime call\n");
  if (clk_id == CLOCK_REALTIME){
    double sec = MSG_get_clock();
    tp->tv_sec = floor(sec);
    tp->tv_nsec = (sec - floor(sec))*pow(10,9);
    printf("%d %ld\n", tp->tv_sec, tp->tv_nsec);
  }

  if ((clk_id == CLOCK_MONOTONIC) ||
      (clk_id == CLOCK_PROCESS_CPUTIME_ID) ||
      (clk_id == CLOCK_THREAD_CPUTIME_ID))
    printf("[%d] [clock_gettime] Unhandled clock\n",getpid());
  else
    printf("[%d] [clock_gettime] This clock does not exist\n",getpid());

  LogWrap("clock_gettime done call\n");
    
  return 0;
}

int clock_settime(clockid_t clk_id, const struct timespec *tp){
  printf("[%d] [clock_settime] Unhandled function\n",getpid());
  return 0;
}
