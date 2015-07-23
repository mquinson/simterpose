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

/** @brief retrieve the arguments of recvfrom syscall */
void get_args_recvfrom(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);

  arg->ret = (ssize_t) reg->ret;
  arg->sockfd = (int) reg->arg[0];
  arg->len = (size_t) reg->arg[2];
  arg->flags = (int) reg->arg[3];

  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  if ( (int) reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(child, &arg->sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(child, &arg->sau, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(child, &arg->snl, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
  } else
    arg->is_addr = 0;

  arg->dest = (void *) reg->arg[1];

  socklen_t len = 0;
  if ( (int) reg->arg[4] != 0) {         // syscall "recv" doesn't exist on x86_64, it's recvfrom with struct sockaddr=NULL and addrlen=0
    ptrace_cpy(child, &len, (void *) reg->arg[5], sizeof(socklen_t), "recvfrom");
  }
  arg->addrlen = len;
}

/** @brief retrieve the arguments of recvmsg syscall */
void get_args_recvmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  pid_t pid = proc->pid;

  arg->sockfd = (int) reg->arg[0];
  arg->flags = (int) reg->arg[2];
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg[1], sizeof(struct msghdr), "recvmsg");

  arg->len = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");
    arg->len += temp.iov_len;
  }
}

/** @brief put the message received in the registers of recvmsg syscall */
void sys_build_recvmsg(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  pid_t pid = proc->pid;
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  ptrace_restore_syscall(pid, SYS_recvmsg, arg->ret);

  int length = arg->ret;
  int global_size = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    if (length < 0)
      break;

    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");

    if (length < temp.iov_len)
      temp.iov_len = length;

    ptrace_poke(pid, arg->msg.msg_iov + i * sizeof(struct iovec), &temp, sizeof(struct iovec));

    ptrace_poke(pid, temp.iov_base, (char *) arg->data + global_size, temp.iov_len);

  }
  free(arg->data);
}



/** @brief translate the port and address of the entering recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the global
 * simulated address and port the application wants to receive the message
 * from. We translate them to real local ones and put the result back in the
 * registers to actually get the recvfrom syscall performed by the kernel.
 */
void sys_translate_recvfrom_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if ( (int) reg.arg[4] == 0)
    return;

  struct sockaddr_in temp = arg->sai;
  int port = get_real_port(proc, temp.sin_addr.s_addr, ntohs(temp.sin_port));
  temp.sin_addr.s_addr = inet_addr("127.0.0.1");
  temp.sin_port = htons(port);
  ptrace_poke(pid, (void *) reg.arg[4], &temp, sizeof(struct sockaddr_in));
  arg->sai = temp;
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

/** @brief translate the port and address of the exiting recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we received the message from. We translate them
 * into global simulated ones and put the result back in the registers, so
 * that the application gets wronged.
 */
void sys_translate_recvfrom_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if ( (int) reg.arg[4] == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(arg->sai.sin_port));
  arg->sai.sin_port = htons(td->port_num);
  arg->sai.sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg.arg[4], &(arg->sai), sizeof(struct sockaddr_in));
}
