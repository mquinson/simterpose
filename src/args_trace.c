/* args_trace -- Retrieve the syscall arguments from registers, and
   build new ones */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <sys/uio.h>

#include <xbt/log.h>

#include "args_trace.h"
#include "sockets.h"
#include "data_utils.h"
#include "simterpose.h"
#include "sysdep.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(ARGS_TRACE, simterpose, "args trace log");

