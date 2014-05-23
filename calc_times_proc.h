#ifndef __CALC_TIMES_PROC_H_
#define __CALC_TIMES_PROC_H_

#include "sysdep.h"

/* gettime.c
 *
 * Utility to get times of a specified tid
 * Slightly changed program from Documentation/getstats.c in Linux kernel
 *
 * Copyright (C) Shailabh Nagar, IBM Corp. 2005
 * Copyright (C) Balbir Singh, IBM Corp. 2006
 * Copyright (c) Jay Lan, SGI. 2006
 * Changed by Tomasz Buchert
 *
 * Compile with
 *	gcc gettime.c -o gettime
 */


void cputimer_init();

void cputimer_exit();

void cputimer_get(int tid, long long int *times);


#endif
