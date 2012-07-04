#ifndef __ARGS_TRACE_H 
#define __ARGS_TRACE_H

#include "ptrace_utils.h"
#include "sockets.h"
#include "sysdep.h"

typedef union{
  struct{
    int sockfd;
    int ret;
    union{
      struct sockaddr_in * psai;
      struct sockaddr_un * psau;
      struct sockaddr_nl * psnl;
    };
    socklen_t addrlen;
  }connect;
}syscall_arg_u;

extern int nb_procs;

void get_args_socket(pid_t child, reg_s *arg);

void get_args_bind_connect(pid_t child, int syscall, reg_s *reg,  syscall_arg_u *arg);

//Return the pid of which socket is accept
pid_t get_args_accept(pid_t child, reg_s *arg);

void get_args_listen(pid_t child, reg_s *arg);

int get_args_send_recv(pid_t child, int syscall, reg_s *arg);

double get_args_select(pid_t child, reg_s *r);

//There's no need to pass more argument because process_desc already contain argument
void sys_build_select(pid_t pid, int match);

double get_args_poll(pid_t child, reg_s* arg);

void get_args_get_setsockopt(pid_t child, int syscall, reg_s* arg);

int get_args_sendto_recvfrom(pid_t child, int syscall, reg_s* arg);

int get_args_send_recvmsg(pid_t child, int syscall, reg_s* arg);

#endif

