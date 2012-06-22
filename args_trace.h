#ifndef __ARGS_TRACE_H 
#define __ARGS_TRACE_H

#include "ptrace_utils.h"
#include "sockets.h"
#include "sysdep.h"

 
extern int nb_procs;

void get_args_socket(pid_t child, syscall_arg *arg);

void get_args_bind_connect(pid_t child, int syscall, syscall_arg *arg);

void get_args_accept(pid_t child, syscall_arg *arg);

void get_args_listen(pid_t child, syscall_arg *arg);

int get_args_send_recv(pid_t child, int syscall, syscall_arg *arg);

void get_args_select(pid_t child, syscall_arg *r);

void get_args_poll(pid_t child, void * src, nfds_t nfds);

void get_args_get_setsockopt(pid_t child, int syscall, syscall_arg* arg);

int get_args_sendto_recvfrom(pid_t child, int syscall, syscall_arg* arg);

int get_args_send_recvmsg(pid_t child, int syscall, syscall_arg* arg);

#endif

