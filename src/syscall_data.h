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

typedef struct recv_arg_s {
	int sockfd;
	int ret;
	size_t len;
	int flags;
} recv_arg_s, send_arg_s;

typedef recv_arg_s *recv_arg_t;
typedef send_arg_s *send_arg_t;


typedef struct recvmsg_arg_s {
	int sockfd;
	int ret;
	int len;
	void *data;
	int flags;
	struct msghdr msg;
} recvmsg_arg_s, sendmsg_arg_s;

typedef sendmsg_arg_s *sendmsg_arg_t;
typedef recvmsg_arg_s *recvmsg_arg_t;


typedef struct select_arg_s {
	int fd_state;
	int maxfd;
	int ret;
	fd_set fd_read;
	fd_set fd_write;
	fd_set fd_except;
	double timeout;
} select_arg_s;

typedef select_arg_s *select_arg_t;


typedef struct poll_arg_s {
	int nbfd;
	struct pollfd *fd_list;
	double timeout;
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
	int ret;
	int len;
	void *data;
	int flags;
	int addrlen;
	void *dest;                   //address in processus of data
	int is_addr;                  //indicate if struct sockadrr is null or not
	union {
		struct sockaddr_in sai;
		struct sockaddr_un sau;
		struct sockaddr_nl snl;
	};
} sendto_arg_s, recvfrom_arg_s;

typedef sendto_arg_s *sendto_arg_t;
typedef recvfrom_arg_s *recvfrom_arg_t;


typedef struct connect_bind_arg_s {
	int sockfd;
	int ret;
	union {
		struct sockaddr_in sai;
		struct sockaddr_un sau;
		struct sockaddr_nl snl;
	};
	socklen_t addrlen;
} connect_arg_s, bind_arg_s;

typedef connect_arg_s *connect_arg_t;
typedef bind_arg_s *bind_arg_t;


typedef struct accept_arg_s {
	int sockfd;
	int ret;
	union {
		struct sockaddr_in sai;
		struct sockaddr_un sau;
		struct sockaddr_nl snl;
	};
	socklen_t addrlen;
	void *addr_dest;
	void *len_dest;
} accept_arg_s;

typedef accept_arg_s *accept_arg_t;

typedef struct socket_arg_s {
	int ret;
	int domain;
	int type;
	int protocol;
} socket_arg_s;

typedef socket_arg_s *socket_arg_t;

typedef struct listen_arg_s {
	int sockfd;
	int backlog;
	int ret;
} listen_arg_s;

typedef listen_arg_s *listen_arg_t;

typedef struct getsockopt_arg_s {
	int sockfd;
	int level;
	int optname;
	void *optval;
	socklen_t optlen;
	int ret;
	void *dest;
	void *dest_optlen;
} getsockopt_arg_s, setsockopt_arg_s;

typedef getsockopt_arg_s *getsockopt_arg_t;
typedef setsockopt_arg_s *setsockopt_arg_t;


typedef struct fcntl_arg_s {
	int fd;
	int cmd;
	int arg;                      //TODO put an union to handle various type of argument
	int ret;
} fcntl_arg_s;

typedef struct fcntl_arg_s *fcntl_arg_t;


typedef struct write_arg_s {
	int fd;
	int ret;
	int count;
	void *data;
	void *dest;
} write_arg_s, read_arg_s;

typedef write_arg_s *write_arg_t;
typedef read_arg_s *read_arg_t;


typedef struct shutdown_arg_s {
	int fd;
	int how;
	int ret;
} shutdown_arg_s;

typedef shutdown_arg_s *shutdown_arg_t;


typedef struct getpeername_arg_s {
	int sockfd;
	struct sockaddr_in in;
	void *sockaddr_dest;
	socklen_t len;
	void *len_dest;
	int ret;
} getpeername_arg_s;

typedef getpeername_arg_s *getpeername_arg_t;


typedef struct time_arg_s {
	time_t ret;
} time_arg_s;

typedef time_arg_s *time_arg_t;


typedef struct gettimeofday_arg_s {
	int ret;
	struct timeval *tv;
	struct timezone *tz;
} gettimeofday_arg_s;
typedef gettimeofday_arg_s *gettimeofday_arg_t;


typedef struct clockgettime_arg_s {
	int ret;
	struct timespec *tp;
} clockgettime_arg_s;
typedef clockgettime_arg_s *clockgettime_arg_t;


typedef struct clone_arg_s {
	int ret;
	unsigned long clone_flags;
	unsigned long newsp;
	void *parent_tid;
	void *child_tid;
} clone_arg_s;
typedef clone_arg_s *clone_arg_t;

typedef struct execve_arg_s {
	int ret;
	long ptr_filename;
	long ptr_argv;
} execve_arg_s;
typedef execve_arg_s *execve_arg_t;

typedef struct open_arg_s {
	int ret;
	long ptr_filename;
	int flags;
	int mode;
} open_arg_s;
typedef open_arg_s *open_arg_t;

typedef union {
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
	pipe_arg_s pipe;
	select_arg_s select;
	fcntl_arg_s fcntl;
	read_arg_s read;
	write_arg_s write;
	shutdown_arg_s shutdown;
	getpeername_arg_s getpeername;
	time_arg_s time;
	gettimeofday_arg_s gettimeofday;
	clockgettime_arg_s clockgettime;
	clone_arg_s clone;
	execve_arg_s execve;
	open_arg_s open;
} syscall_arg_u;


#endif
