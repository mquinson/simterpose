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

#include "include/simterpose.h"

/* Function allowing to log every wrapped functions */
static void LogWrap(const char *mess){
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

int gettimeofday (struct timeval *__restrict __tv, __timezone_ptr_t __tz){
  ABORT("This function is obsolescent, call clock_gettime().");
  return 0;
}

struct tm * localtime(const time_t *timep){
  ABORT("localtime: Unhandled function.");
  return NULL;
}

time_t mktime(struct tm *tm){
  ABORT("mktime: Unhandled function.");
  return 0;
}

int clock_getres(clockid_t clk_id, struct timespec *res){
  ABORT("clock_getres: Unhandled function.");
  return 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp){
  if ((clk_id == CLOCK_MONOTONIC) ||
      (clk_id == CLOCK_PROCESS_CPUTIME_ID) ||
      (clk_id == CLOCK_THREAD_CPUTIME_ID))
     ABORT("clock_gettime: Unhandled clock.");
  else
     ABORT("clock_gettime: This clock does not exist.");

  LogWrap("clock_gettime call\n");
  if (clk_id == CLOCK_REALTIME){
    double sec = MSG_get_clock();
    tp->tv_sec = (time_t) floor(sec);
    tp->tv_nsec = (sec - floor(sec))*pow(10,9);
  }
  LogWrap("clock_gettime done call\n");
    
  return 0;
}

int clock_settime(clockid_t clk_id, const struct timespec *tp){
   ABORT("clock_settime: Unhandled function.");
  return 0;
}
