/* sys_recvfrom -- Handlers recvfrom syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

void syscall_recvfrom(reg_s * reg, process_descriptor_t * proc);
void syscall_recvfrom_pre(reg_s * reg, process_descriptor_t * proc, void * data, void * dest, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);
void syscall_recvfrom_post(reg_s * reg, process_descriptor_t * proc, void * data, void * dest, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);
void process_recvfrom_out_call(reg_s * reg, process_descriptor_t * proc, void * data, void * dest, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl, int is_addr, socklen_t addrlen);

void sys_translate_recvfrom_out(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai);
