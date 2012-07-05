#ifndef __ARGS_TRACE_H 
#define __ARGS_TRACE_H

#include "sysdep.h"

typedef struct connect_bind_arg_s connect_arg_s;
typedef connect_arg_s* connect_arg_t;

typedef struct connect_bind_arg_s bind_arg_s;
typedef bind_arg_s* bind_arg_t;

typedef struct accept_arg_s accept_arg_s;
typedef accept_arg_s* accept_arg_t;

typedef struct socket_arg_s socket_arg_s;
typedef socket_arg_s* socket_arg_t;

typedef struct listen_arg_s listen_arg_s;
typedef listen_arg_s* listen_arg_t;

typedef struct getsockopt_arg_s getsockopt_arg_s;
typedef getsockopt_arg_s* getsockopt_arg_t;

typedef struct getsockopt_arg_s setsockopt_arg_s;
typedef setsockopt_arg_s* setsockopt_arg_t;

typedef struct select_arg_s select_arg_s;
typedef select_arg_s* select_arg_t;

typedef struct poll_arg_s poll_arg_s;
typedef poll_arg_s* poll_arg_t;

typedef struct recv_arg_s recv_arg_s;
typedef recv_arg_s* recv_arg_t;

typedef struct recv_arg_s send_arg_s;
typedef send_arg_s* send_arg_t;

typedef struct sendto_arg_s sendto_arg_s;
typedef sendto_arg_s* sendto_arg_t;

typedef struct sendto_arg_s recvfrom_arg_s;
typedef recvfrom_arg_s* recvfrom_arg_t;

struct recv_arg_s{
  int sockfd;
  size_t len;
  int flags;
  int ret;
};

struct select_arg_s{
  int fd_state;
  int maxfd;
  fd_set fd_read;
  fd_set fd_write;
  fd_set fd_except;
};

struct poll_arg_s{
  int nbfd;
  struct pollfd* fd_list;
};

struct sendto_arg_s{
  int sockfd;
  int len;
  int flags;
  int addrlen;
  int is_addr;//indicate if struct sockadrr is null or not
  union{
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
  int ret;
};

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

struct listen_arg_s{
  int sockfd;
  int backlog;
  int ret;
};

struct getsockopt_arg_s{
  int sockfd;
  int level;
  int optname;
  //void *optval;
  socklen_t optlen;
  int ret;
};

typedef union{
  connect_arg_s connect;
  bind_arg_s bind;
  accept_arg_s accept;
  socket_arg_s socket;
  getsockopt_arg_s getsockopt;
  setsockopt_arg_s setsockopt;
  listen_arg_s listen;
  recv_arg_s recv;
  send_arg_s send;
  sendto_arg_s sendto;
  recvfrom_arg_s recvfrom;
} syscall_arg_u;

#include "ptrace_utils.h"
#include "sockets.h"

extern int nb_procs;

void get_args_socket(pid_t child, reg_s *arg, syscall_arg_u* sysarg);

void get_args_bind_connect(pid_t child, int syscall, reg_s *reg, syscall_arg_u *arg);

//Return the pid of which socket is accept
void get_args_accept(pid_t child, reg_s *reg, syscall_arg_u *arg);

void get_args_listen(pid_t child, reg_s *reg, syscall_arg_u *sysarg);

void get_args_send_recv(pid_t child, int syscall, reg_s *reg, syscall_arg_u *arg);

double get_args_select(pid_t child, reg_s *r);

//There's no need to pass more argument because process_desc already contain argument
void sys_build_select(pid_t pid, int match);

double get_args_poll(pid_t child, reg_s* arg);

void get_args_get_setsockopt(pid_t child, int syscall, reg_s* reg, syscall_arg_u *sysarg);

void get_args_sendto_recvfrom(pid_t child, int syscall, reg_s* arg, syscall_arg_u* sysarg);

int get_args_send_recvmsg(pid_t child, int syscall, reg_s* arg);

#endif

