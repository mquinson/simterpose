/* sys_sendto -- Handlers sendto syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

int syscall_sendto(reg_s * reg, process_descriptor_t * proc);
int syscall_sendto_pre(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);
int syscall_sendto_post(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);

void sys_translate_sendto_in(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);
void sys_translate_sendto_out(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);
