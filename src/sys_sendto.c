/* sys_sendto -- Handles sendto syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_sendto.h"

#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles sendto syscall at the entrance and the exit */
int syscall_sendto(pid_t pid, reg_s * reg, process_descriptor_t * proc){

  int ret = 0;
  struct sockaddr_in * sai = (struct sockaddr_in *) xbt_malloc0(sizeof(struct sockaddr_in));
  struct sockaddr_un * sau = (struct sockaddr_un *) xbt_malloc0(sizeof(struct sockaddr_un));
  struct sockaddr_nl * snl = (struct sockaddr_nl *) xbt_malloc0(sizeof(struct sockaddr_nl));
  
  if (proc_entering(proc))
    ret = syscall_sendto_pre(pid, reg, proc, sai, sau, snl);
  else
    ret = syscall_sendto_post(pid, reg, proc, sai, sau, snl);
  if (ret)
    return ret;

  return 0;
}

/** @brief handles sendto syscall at the entrance
 *
 * In case of full mediation, we retrieve the message intended to be sent by
 * the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_sendto_post afterwards.
 *
 * In case of address translation we translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall
 */
int syscall_sendto_pre(pid_t pid, reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  proc_inside(proc);
  //  XBT_DEBUG("[%d] sendto_pre", pid);
  XBT_DEBUG("sendto_pre");
  void * data = NULL;
  size_t len_buf;
  socklen_t addrlen = 0;
  int is_addr = 0;

  if((get_type_socket(proc, (int) reg->arg[0]) != SOCK_STREAM)
     && (get_type_socket(proc, (int) reg->arg[0]) != SOCK_SEQPACKET))
    {
      int domain = get_domain_socket(proc, (int) reg->arg[0]);
      if ( (int) reg->arg[4] != 0) {  
	is_addr = 1;
	if (domain == 2)            // PF_INET
	  ptrace_cpy(pid, sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "sendto");
	if (domain == 1)            // PF_UNIX
	  ptrace_cpy(pid, sau, (void *) reg->arg[4], sizeof(struct sockaddr_un), "sendto");
	if (domain == 16)           // PF_NETLINK
	  ptrace_cpy(pid, snl, (void *) reg->arg[4], sizeof(struct sockaddr_nl), "sendto");
      } else
	is_addr = 0;

      if ( (int) reg->arg[4] != 0) {  
	addrlen = (socklen_t) reg->arg[5];
      } else
	addrlen = 0;
    
    }
  
#ifndef address_translation
  data = xbt_new0(char, (size_t) reg->arg[2]);
  ptrace_cpy(pid, data, (void *) reg->arg[1],  (size_t) reg->arg[2], "sendto");

  process_descriptor_t remote_proc;
  if (process_send_call(reg, proc, &remote_proc, data)) {
    ptrace_neutralize_syscall(pid);

    proc_outside(proc);
    ptrace_restore_syscall(pid, SYS_sendto, (int) reg->ret);

    if (strace_option)
      print_sendto_syscall(reg, proc, data, is_addr, addrlen, sai, sau, snl);
    return PROCESS_TASK_FOUND;
  }
#else
  if (socket_registered(proc, (int) reg->arg[0]) != -1) {
    if (socket_network(proc, (int) reg->arg[0])){
      if((get_type_socket(proc, (int) reg->arg[0]) != SOCK_STREAM)
	 && (get_type_socket(proc, (int) reg->arg[0]) != SOCK_SEQPACKET))
	sys_translate_sendto_in(reg, proc, sai, sau, snl);
    }
  }
#endif
  return PROCESS_CONTINUE;
}

/** @brief handles sendto syscall at the exit
 *
 * In case of address translation we translate the arguments back (from the
 * real local address to the global simulated one) to wrong the application.
 * We also send the MSG task in order to return control to the MSG process
 * receiving the message
 */
int syscall_sendto_post(pid_t pid, reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] sendto_out", pid);
  XBT_DEBUG("sendto_post");
  void * data = NULL;
  socklen_t addrlen = 0;
  int is_addr = 0;  
  
  if((get_type_socket(proc, (int) reg->arg[0]) != SOCK_STREAM)
     && (get_type_socket(proc, (int) reg->arg[0]) != SOCK_SEQPACKET))
    {      
      int domain = get_domain_socket(proc, (int) reg->arg[0]);
      if ( (int) reg->arg[4] != 0) {
	is_addr = 1;
	if (domain == 2)            // PF_INET
	  ptrace_cpy(pid, &sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "sendto");
	if (domain == 1)            // PF_UNIX
	  ptrace_cpy(pid, &sau, (void *) reg->arg[4], sizeof(struct sockaddr_un), "sendto");
	if (domain == 16)           // PF_NETLINK
	  ptrace_cpy(pid, &snl, (void *) reg->arg[4], sizeof(struct sockaddr_nl), "sendto");
      } else
	is_addr = 0;
  
      if ( (int) reg->arg[4] != 0) { 
	addrlen = (socklen_t) reg->arg[5];
      } else
	addrlen = 0;
    }

  if (strace_option)
    print_sendto_syscall(reg, proc, data, is_addr, addrlen, sai, sau, snl);

  if (socket_registered(proc, (int) reg->arg[0]) != -1) {
    if (socket_network(proc, (int) reg->arg[0])) {
        if((get_type_socket(proc, (int) reg->arg[0]) != SOCK_STREAM)
	   && (get_type_socket(proc, (int) reg->arg[0]) != SOCK_SEQPACKET))
	  sys_translate_sendto_out(reg, proc, sai, sau, snl);
    }
  }
  if ((int) reg->ret > 0) {
    process_descriptor_t remote_proc;
    if (process_send_call(reg, proc, &remote_proc, data))
      return PROCESS_TASK_FOUND;
  }
  
  return PROCESS_CONTINUE;
}

/** @brief translate the port and address of the entering sendto syscall
 *
 * We take the arguments in the registers, which correspond to the global
 * simulated address and port the application wants to send the message to.
 * We translate them to real local ones and put the result back in the
 * registers to actually get the sendto syscall performed by the kernel.
 */
void sys_translate_sendto_in(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  pid_t pid = proc->pid;

  if ((int) reg->arg[4] == 0)
    return;

  struct in_addr in = { sai->sin_addr.s_addr };
  XBT_DEBUG("Translate address %s:%d", inet_ntoa(in), ntohs(sai->sin_port));

  struct sockaddr_in * temp = sai;
  ntohs(temp->sin_port);
  int port = get_real_port(proc, temp->sin_addr.s_addr, ntohs(temp->sin_port));
  temp->sin_addr.s_addr = inet_addr("127.0.0.1");
  temp->sin_port = htons(port);
  ptrace_poke(pid, (void *) reg->arg[4], &temp, sizeof(struct sockaddr_in));
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

/** @brief translate the port and address of the exiting sendto syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we sent the message to. We translate them into global
 * simulated ones and put the result back in the registers, so that the
 * application gets wronged.
 */
void sys_translate_sendto_out(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  pid_t pid = proc->pid;

  if ( (int) reg->arg[4] == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(sai->sin_port));
  sai->sin_port = htons(td->port_num);
  sai->sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg->arg[4], &sai, sizeof(struct sockaddr_in));
}
