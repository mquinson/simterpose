/* syscall_data -- Structures to store syscall arguments */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef SYSCALL_DATA_H
#define SYSCALL_DATA_H

/* Q. Where does this data come from?
 * A. From the linux source code itself. See for example:
 *    http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64
 *
 * Excerpt of that page:
 *
 * To find the implementation of a system call, grep the kernel tree for SYSCALL_DEFINE.\?(syscall,
 * For example, to find the read system call:
 *
 *   illusion:/usr/src/linux-source-3.2.0$ grep -rA3 'SYSCALL_DEFINE.\?(read,' *
 *   fs/read_write.c:SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 *   fs/read_write.c-{
 *   fs/read_write.c-        struct file *file;
 *   fs/read_write.c-        ssize_t ret = -EBADF;
 *
 * The results show that the implementation is in fs/read_write.c and that it takes 3 arguments (thus SYSCALL_DEFINE3).
 *
 */

#include "sysdep.h"

#define SELECT_FDRD_SET 0x01
#define SELECT_FDWR_SET 0x02
#define SELECT_FDEX_SET 0x04

typedef struct recvmsg_arg_s {
  int sockfd;
  size_t len;
  void *data;
  int flags;
  struct msghdr msg;
  ssize_t ret;
} recvmsg_arg_s, sendmsg_arg_s;

typedef sendmsg_arg_s *sendmsg_arg_t;
typedef recvmsg_arg_s *recvmsg_arg_t;


typedef struct select_arg_s {
  int maxfd;
  fd_set fd_read;
  fd_set fd_write;
  fd_set fd_except;
  double timeout;
  int fd_state;
  int ret;
} select_arg_s;

typedef select_arg_s *select_arg_t;


typedef struct poll_arg_s {
  struct pollfd *fd_list;
  nfds_t nfds;
  int timeout;
  int ret;
} poll_arg_s;

typedef poll_arg_s *poll_arg_t;


typedef struct pipe_arg_s {
  int *filedes;
  int ret;
} pipe_arg_s;

typedef pipe_arg_s *pipe_arg_t;



typedef struct sendto_arg_s {
  int sockfd;
  void *data;
  size_t len;
  int flags;
  socklen_t addrlen;
  void *dest;                   //address in processus of data
  int is_addr;                  //indicate if struct sockadrr is null or not
 union {
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
  ssize_t ret;
} sendto_arg_s, recvfrom_arg_s;

typedef sendto_arg_s *sendto_arg_t;
typedef recvfrom_arg_s *recvfrom_arg_t;


typedef struct connect_bind_arg_s {
  int sockfd;
  union {
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
  socklen_t addrlen;
  int ret;
} connect_arg_s, bind_arg_s;

typedef connect_arg_s *connect_arg_t;
typedef bind_arg_s *bind_arg_t;


typedef struct accept_arg_s {
  int sockfd;
  union {
    struct sockaddr_in sai;
    struct sockaddr_un sau;
    struct sockaddr_nl snl;
  };
  socklen_t addrlen;
  void *addr_dest;
  void *len_dest;
  int ret;
} accept_arg_s;

typedef accept_arg_s *accept_arg_t;

typedef struct socket_arg_s {
  int domain;
  int type;
  int protocol;
  int ret;
} socket_arg_s;

typedef socket_arg_s *socket_arg_t;

typedef struct getsockopt_arg_s {
  int sockfd;
  int level;
  int optname;
  void *optval;
  socklen_t optlen;
  void *dest;
  void *dest_optlen;
  int ret;
} getsockopt_arg_s, setsockopt_arg_s;

typedef getsockopt_arg_s *getsockopt_arg_t;
typedef setsockopt_arg_s *setsockopt_arg_t;


typedef struct fcntl_arg_s {
  int fd;
  int cmd;
  union{
    long cmd_arg;
    struct f_owner_ex * owner;
    struct flock * lock;
  } arg;
  int ret;
} fcntl_arg_s;

typedef struct fcntl_arg_s *fcntl_arg_t;


typedef struct write_arg_s {
  int fd;
  void *data;
  size_t count;
  void *dest; /* TODO weird what is this?*/
  ssize_t ret;
} write_arg_s, read_arg_s;

typedef write_arg_s *write_arg_t;
typedef read_arg_s *read_arg_t;


typedef struct shutdown_arg_s {
  int fd;
  int how;
  int ret;
} shutdown_arg_s;

typedef shutdown_arg_s *shutdown_arg_t;

typedef struct clone_arg_s { /* TODO missing argument*/
  unsigned long newsp;
  void *parent_tid;
  void *child_tid;
  int flags;
  int ret;
} clone_arg_s;
typedef clone_arg_s *clone_arg_t;

typedef union {
  connect_arg_s connect;
  bind_arg_s bind;
  accept_arg_s accept;
  socket_arg_s socket;
  getsockopt_arg_s getsockopt;
  setsockopt_arg_s setsockopt;
  sendto_arg_s sendto;
  recvfrom_arg_s recvfrom;
  recvmsg_arg_s recvmsg;
  sendmsg_arg_s sendmsg;
  poll_arg_s poll;
  pipe_arg_s pipe;
  select_arg_s select;
  fcntl_arg_s fcntl;
  read_arg_s read;
  write_arg_s write;
  shutdown_arg_s shutdown;
  clone_arg_s clone;
} syscall_arg_u;


#endif
