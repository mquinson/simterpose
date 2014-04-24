#ifndef SYSCALL_DATA_INCLUDE
#define SYSCALL_DATA_INCLUDE

#include "sysdep.h"

#define SELECT_FDRD_SET 0x01
#define SELECT_FDWR_SET 0x02
#define SELECT_FDEX_SET 0x04

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

typedef struct recvmsg_arg_s sendmsg_arg_s;
typedef sendmsg_arg_s* sendmsg_arg_t;

typedef struct recvmsg_arg_s recvmsg_arg_s;
typedef recvmsg_arg_s* recvmsg_arg_t;

typedef struct fcntl_arg_s fcntl_arg_s;
typedef struct fcntl_arg_s* fcntl_arg_t;

typedef struct write_arg_s write_arg_s;
typedef write_arg_s* write_arg_t;

typedef struct write_arg_s read_arg_s;
typedef read_arg_s* read_arg_t;

typedef struct shutdown_arg_s shutdown_arg_s;
typedef shutdown_arg_s* shutdown_arg_t;

typedef struct getpeername_arg_s getpeername_arg_s;
typedef getpeername_arg_s* getpeername_arg_t;

typedef struct time_arg_s time_arg_s;
typedef time_arg_s *time_arg_t;

typedef struct gettimeofday_arg_s gettimeofday_arg_s;
typedef gettimeofday_arg_s *gettimeofday_arg_t;


struct recv_arg_s{
  int sockfd;
  int ret;
  size_t len;
  int flags;
};

struct recvmsg_arg_s{
  int sockfd;
  int ret;
  int len;
  void* data;
  int flags;
  struct msghdr msg;
};

struct select_arg_s{
  int fd_state;
  int maxfd;
  int ret;
  fd_set fd_read;
  fd_set fd_write;
  fd_set fd_except;
  double timeout;
};

struct poll_arg_s{
  int nbfd;
  struct pollfd* fd_list;
  double timeout;
  int ret;
};

struct sendto_arg_s{
  int sockfd;
  int ret;
  int len;
  void* data;
  int flags;
  int addrlen;
  void* dest; //address in processus of data
  int is_addr;//indicate if struct sockadrr is null or not
  union{
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
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
  void *addr_dest;
  void *len_dest;
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
  void *optval;
  socklen_t optlen;
  int ret;
  void *dest;
  void *dest_optlen;
};

struct fcntl_arg_s{
  int fd;
  int cmd;
  int arg;//TODO put an union to handle various type of argument
  int ret;
};

struct write_arg_s{
  int fd;
  int ret;
  int count;
  void* data;
  void* dest;
};

struct shutdown_arg_s{
  int fd;
  int how;
  int ret;
};

struct getpeername_arg_s{
  int sockfd;
  struct sockaddr_in in;
  void* sockaddr_dest;
  socklen_t len;
  void* len_dest;
  int ret;
};


struct time_arg_s{
  time_t t;
  void * t_dest;
  time_t ret;
};

struct gettimeofday_arg_s{
  int ret;
  struct timeval *tv;
  struct timeval *tv_dest;
  struct timezone *tz;
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
  recvmsg_arg_s recvmsg;
  sendmsg_arg_s sendmsg;
  poll_arg_s poll;
  select_arg_s select;
  fcntl_arg_s fcntl;
  read_arg_s read;
  write_arg_s write;
  shutdown_arg_s shutdown;
  getpeername_arg_s getpeername;
  time_arg_s time;
  gettimeofday_arg_s gettimeofday;
} syscall_arg_u;


#endif
