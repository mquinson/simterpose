/* cputimer -- retrieve the cputime of a given thread using netlink        */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */

#ifndef CPUTIMER_H
#define CPUTIMER_H

#include "sysdep.h"

typedef struct s_xbt_cpu_timer *xbt_cpu_timer_t;
xbt_cpu_timer_t timer;

xbt_cpu_timer_t cputimer_new(void);
void cputimer_init(xbt_cpu_timer_t timer);
void cputimer_exit(xbt_cpu_timer_t timer);
void cputimer_get(int tid, long long int *times, xbt_cpu_timer_t timer);

#endif
