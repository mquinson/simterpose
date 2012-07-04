#ifndef __ARGS_TRACE_H 
#define __ARGS_TRACE_H

typedef struct connect_bind_arg_s connect_arg_s;
typedef connect_arg_s* connect_arg_t;

typedef struct connect_bind_arg_s bind_arg_s;
typedef bind_arg_s* bind_arg_t;

typedef struct accept_arg_s accept_arg_s;
typedef accept_arg_s* accept_arg_t;

typedef struct socket_arg_s socket_arg_s;
typedef socket_arg_s* socket_arg_t;

#include "ptrace_utils.h"
#include "sockets.h"
#include "sysdep.h"

struct connect_bind_arg_s{
  int sockfd;
  int ret;
  union{
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
  socklen_t addrlen;
};

struct accept_arg_s{
  int sockfd;
  int ret;
  union{
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
  socklen_t addrlen;
};

struct socket_arg_s{
  int ret;
  int domain;
  int type;
  int protocol;
};

typedef union{
  connect_arg_s connect;
  bind_arg_s bind;
  accept_arg_s accept;
  socket_arg_s socket;
} syscall_arg_u;


extern int nb_procs;

void get_args_socket(pid_t child, reg_s *arg, syscall_arg_u* sysarg);

void get_args_bind_connect(pid_t child, int syscall, reg_s *reg, syscall_arg_u *arg);

//Return the pid of which socket is accept
pid_t get_args_accept(pid_t child, reg_s *reg, syscall_arg_u *arg);

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

