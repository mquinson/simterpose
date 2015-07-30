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

/** @brief retrieve the arguments of recvmsg syscall */
/* void get_args_recvmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg) */
/* { */
/*   recvmsg_arg_t arg = &(sysarg->recvmsg); */
/*   pid_t pid = proc->pid; */

/*   arg->sockfd = (int) reg->arg[0]; */
/*   arg->flags = (int) reg->arg[2]; */
/*   ptrace_cpy(pid, &arg->msg, (void *) reg->arg[1], sizeof(struct msghdr), "recvmsg"); */

/*   arg->len = 0; */
/*   int i; */
/*   for (i = 0; i < arg->msg.msg_iovlen; ++i) { */
/*     struct iovec temp; */
/*     ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg"); */
/*     arg->len += temp.iov_len; */
/*   } */
/* } */
