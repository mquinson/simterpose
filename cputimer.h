/* cputimer -- retrieve the cputime of a given thread using netlink        */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */

#ifndef CPUTIMER_H
#define CPUTIMER_H

#include "sysdep.h"

void cputimer_init();
void cputimer_exit();
void cputimer_get(int tid, long long int *times);

#endif
