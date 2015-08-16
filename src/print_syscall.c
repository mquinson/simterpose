/* print_syscall -- Functions to print a strace-like log of
   syscalls */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <stdio.h>
#include <linux/sched.h>   /* For clone flags */
#include <sys/types.h>
#include <unistd.h>

#include <xbt.h>

#include "print_syscall.h"
#include "ptrace_utils.h"
#include "sockets.h"
#include "simterpose.h"
#include "sysdep.h"

typedef struct {
  int val;
  const char* name;
} flag_names_t;
#define FLAG_NAME(x) { x, #x}
#define FLAG_NAME_EOL {0,NULL}

static flag_names_t flags_open[] = {
  FLAG_NAME(O_RDWR),
  FLAG_NAME(O_RDONLY),
  FLAG_NAME(O_WRONLY),
  FLAG_NAME(O_NONBLOCK),
  FLAG_NAME(O_APPEND),
  FLAG_NAME(O_CREAT),
  FLAG_NAME(O_TRUNC),
  FLAG_NAME(O_EXCL),
  FLAG_NAME(O_NOCTTY),
  FLAG_NAME(O_SYNC),
  FLAG_NAME(O_DSYNC),
  FLAG_NAME(O_RSYNC),
  FLAG_NAME(O_NDELAY),
  FLAG_NAME(O_CLOEXEC),
  FLAG_NAME_EOL
};

static flag_names_t errno_values[] = {
  //grep define /usr/include/asm-generic/errno-base.h|grep [0-9]|sed -e 's/#define[[:space:]]*E/FLAG_NAME(E/' -e 's/[[:space:]].*/),/' -e 's/^/        /'
  FLAG_NAME(EPERM),
  FLAG_NAME(ENOENT),
  FLAG_NAME(ESRCH),
  FLAG_NAME(EINTR),
  FLAG_NAME(EIO),
  FLAG_NAME(ENXIO),
  FLAG_NAME(E2BIG),
  FLAG_NAME(ENOEXEC),
  FLAG_NAME(EBADF),
  FLAG_NAME(ECHILD),
  FLAG_NAME(EAGAIN),
  FLAG_NAME(ENOMEM),
  FLAG_NAME(EACCES),
  FLAG_NAME(EFAULT),
  FLAG_NAME(ENOTBLK),
  FLAG_NAME(EBUSY),
  FLAG_NAME(EEXIST),
  FLAG_NAME(EXDEV),
  FLAG_NAME(ENODEV),
  FLAG_NAME(ENOTDIR),
  FLAG_NAME(EISDIR),
  FLAG_NAME(EINVAL),
  FLAG_NAME(ENFILE),
  FLAG_NAME(EMFILE),
  FLAG_NAME(ENOTTY),
  FLAG_NAME(ETXTBSY),
  FLAG_NAME(EFBIG),
  FLAG_NAME(ENOSPC),
  FLAG_NAME(ESPIPE),
  FLAG_NAME(EROFS),
  FLAG_NAME(EMLINK),
  FLAG_NAME(EPIPE),
  //grep define /usr/include/asm-generic/errno.h|grep [0-9]|sed -e 's/#define[[:space:]]*E/FLAG_NAME(E/' -e 's/[[:space:]].*/),/' -e 's/^/        /'
  FLAG_NAME(EDEADLK),
  FLAG_NAME(ENAMETOOLONG),
  FLAG_NAME(ENOLCK),
  FLAG_NAME(ENOSYS),
  FLAG_NAME(ENOTEMPTY),
  FLAG_NAME(ELOOP),
  FLAG_NAME(ENOMSG),
  FLAG_NAME(EIDRM),
  FLAG_NAME(ECHRNG),
  FLAG_NAME(EL2NSYNC),
  FLAG_NAME(EL3HLT),
  FLAG_NAME(EL3RST),
  FLAG_NAME(ELNRNG),
  FLAG_NAME(EUNATCH),
  FLAG_NAME(ENOCSI),
  FLAG_NAME(EL2HLT),
  FLAG_NAME(EBADE),
  FLAG_NAME(EBADR),
  FLAG_NAME(EXFULL),
  FLAG_NAME(ENOANO),
  FLAG_NAME(EBADRQC),
  FLAG_NAME(EBADSLT),
  FLAG_NAME(EBFONT),
  FLAG_NAME(ENOSTR),
  FLAG_NAME(ENODATA),
  FLAG_NAME(ETIME),
  FLAG_NAME(ENOSR),
  FLAG_NAME(ENONET),
  FLAG_NAME(ENOPKG),
  FLAG_NAME(EREMOTE),
  FLAG_NAME(ENOLINK),
  FLAG_NAME(EADV),
  FLAG_NAME(ESRMNT),
  FLAG_NAME(ECOMM),
  FLAG_NAME(EPROTO),
  FLAG_NAME(EMULTIHOP),
  FLAG_NAME(EDOTDOT),
  FLAG_NAME(EBADMSG),
  FLAG_NAME(EOVERFLOW),
  FLAG_NAME(ENOTUNIQ),
  FLAG_NAME(EBADFD),
  FLAG_NAME(EREMCHG),
  FLAG_NAME(ELIBACC),
  FLAG_NAME(ELIBBAD),
  FLAG_NAME(ELIBSCN),
  FLAG_NAME(ELIBMAX),
  FLAG_NAME(ELIBEXEC),
  FLAG_NAME(EILSEQ),
  FLAG_NAME(ERESTART),
  FLAG_NAME(ESTRPIPE),
  FLAG_NAME(EUSERS),
  FLAG_NAME(ENOTSOCK),
  FLAG_NAME(EDESTADDRREQ),
  FLAG_NAME(EMSGSIZE),
  FLAG_NAME(EPROTOTYPE),
  FLAG_NAME(ENOPROTOOPT),
  FLAG_NAME(EPROTONOSUPPORT),
  FLAG_NAME(ESOCKTNOSUPPORT),
  FLAG_NAME(EOPNOTSUPP),
  FLAG_NAME(EPFNOSUPPORT),
  FLAG_NAME(EAFNOSUPPORT),
  FLAG_NAME(EADDRINUSE),
  FLAG_NAME(EADDRNOTAVAIL),
  FLAG_NAME(ENETDOWN),
  FLAG_NAME(ENETUNREACH),
  FLAG_NAME(ENETRESET),
  FLAG_NAME(ECONNABORTED),
  FLAG_NAME(ECONNRESET),
  FLAG_NAME(ENOBUFS),
  FLAG_NAME(EISCONN),
  FLAG_NAME(ENOTCONN),
  FLAG_NAME(ESHUTDOWN),
  FLAG_NAME(ETOOMANYREFS),
  FLAG_NAME(ETIMEDOUT),
  FLAG_NAME(ECONNREFUSED),
  FLAG_NAME(EHOSTDOWN),
  FLAG_NAME(EHOSTUNREACH),
  FLAG_NAME(EALREADY),
  FLAG_NAME(EINPROGRESS),
  FLAG_NAME(ESTALE),
  FLAG_NAME(EUCLEAN),
  FLAG_NAME(ENOTNAM),
  FLAG_NAME(ENAVAIL),
  FLAG_NAME(EISNAM),
  FLAG_NAME(EREMOTEIO),
  FLAG_NAME(EDQUOT),
  FLAG_NAME(ENOMEDIUM),
  FLAG_NAME(EMEDIUMTYPE),
  FLAG_NAME(ECANCELED),
  FLAG_NAME(ENOKEY),
  FLAG_NAME(EKEYEXPIRED),
  FLAG_NAME(EKEYREVOKED),
  FLAG_NAME(EKEYREJECTED),
  FLAG_NAME(EOWNERDEAD),
  FLAG_NAME(ENOTRECOVERABLE),
  FLAG_NAME(ERFKILL),
  FLAG_NAME(EHWPOISON),
  // End of list
  FLAG_NAME_EOL
};

/** @brief Display the flags that a given syscal may have from a value/name list */
static void print_flags(process_descriptor_t *proc, int flags, flag_names_t *names) {
  int first = 1;
  for (; names->name;names++) {
    if ((names->val & flags) == names->val) {
      if (!first)
	fprintf(proc->strace_out,"|");
      first = 0;
      fprintf(proc->strace_out, "%s", names->name);
      flags &= ~names->val;
    }
  }
  if (flags) {
    if (!first)
      fprintf(proc->strace_out,"|");
    fprintf(proc->strace_out, "%#x", flags);
  }
}


/** @brief print a strace-like log of accept syscall */
void print_accept_syscall(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;
  struct sockaddr_in sai; 
  struct sockaddr_un sau;
  struct sockaddr_nl snl;
  int domain = get_domain_socket(proc, (int) reg->arg[0]);
  fprintf(proc->strace_out,"[%d] accept(", pid);

  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);

  if (domain == 2) {            // PF_INET
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
    fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(sai.sin_port),
	    inet_ntoa(sai.sin_addr));
  } else if (domain == 1) {     //PF_UNIX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_un), "connect");
    fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", sau.sun_path);
  } else if (domain == 16) {    //PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_nl), "connect");
    fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", snl.nl_pid, snl.nl_groups);
  } else {
    fprintf(proc->strace_out, "{sockaddr unknown}, ");
  }

  fprintf(proc->strace_out, "%d",  (socklen_t) reg->arg[2]);
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief print a strace-like log of connect syscall */
void print_connect_syscall(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid; 
  int domain = get_domain_socket(proc, (int) reg->arg[0]);
  struct sockaddr_in sai; 
  struct sockaddr_un sau;
  struct sockaddr_nl snl;
  
  fprintf(proc->strace_out,"[%d] connect(", pid);
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);

  if (domain == 2) {
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
    fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(sai.sin_port),
	    inet_ntoa(sai.sin_addr));
  } else if (domain == 1) {     //PF_UNIX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_un), "connect");
    fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", sau.sun_path);
  } else if (domain == 16) {    //PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_nl), "connect");
    fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", snl.nl_pid, snl.nl_groups);
  } else {
    fprintf(proc->strace_out, "{sockaddr unknown}, ");
  }
  fprintf(proc->strace_out, "%d", (socklen_t) reg->arg[2]);
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief print a strace-like log of bind syscall */
void print_bind_syscall(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;
  int domain = get_domain_socket(proc, (int) reg->arg[0]);
  struct sockaddr_in sai;
  struct sockaddr_un sau;
  struct sockaddr_nl snl;

  fprintf(proc->strace_out,"[%d] bind(", pid);
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);

  if (domain == 2) {
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "bind");
    fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(sai.sin_port),
	    inet_ntoa(sai.sin_addr));
  } else if (domain == 1) {     //PF_UNIX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_un), "bind");
    fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", sau.sun_path);
  } else if (domain == 16) {    //PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_nl), "bind");
    fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", snl.nl_pid, snl.nl_groups);
  } else {
    fprintf(proc->strace_out, "{sockaddr unknown}, ");
  }
  fprintf(proc->strace_out, "%d", (socklen_t) reg->arg[2]);
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief print a strace-like log of socket syscall */
void print_socket_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out,"[%d] socket(", proc->pid);
  switch ((int) reg->arg[0]) {
  case 0:
    fprintf(proc->strace_out, "PF_UNSPEC, ");
    break;
  case 1:
    fprintf(proc->strace_out, "PF_UNIX, ");
    break;
  case 2:
    fprintf(proc->strace_out, "PF_INET, ");
    /* switch (arg->type) { */
    switch ((int) reg->arg[1]) {
    case 1:
      fprintf(proc->strace_out, "SOCK_STREAM, ");
      break;
    case 2:
      fprintf(proc->strace_out, "SOCK_DGRAM, ");
      break;
    case 3:
      fprintf(proc->strace_out, "SOCK_RAW, ");
      break;
    case 4:
      fprintf(proc->strace_out, "SOCK_RDM, ");
      break;
    case 5:
      fprintf(proc->strace_out, "SOCK_SEQPACKET, ");
      break;
    case 6:
      fprintf(proc->strace_out, "SOCK_DCCP, ");
      break;
    case 10:
      fprintf(proc->strace_out, "SOCK_PACKET, ");
      break;
    default:
      fprintf(proc->strace_out, "TYPE UNKNOWN (%d), ", (int) reg->arg[1]);
      break;
    }
    switch ((int) reg->arg[2]) {
    case 0:
      fprintf(proc->strace_out, "IPPROTO_IP");
      break;
    case 1:
      fprintf(proc->strace_out, "IPPROTO_ICMP");
      break;
    case 2:
      fprintf(proc->strace_out, "IPPROTO_IGMP");
      break;
    case 3:
      fprintf(proc->strace_out, "IPPROTO_GGP");
      break;
    case 6:
      fprintf(proc->strace_out, "IPPROTO_TCP");
      break;
    case 17:
      fprintf(proc->strace_out, "IPPROTO_UDP");
      break;
    case 132:
      fprintf(proc->strace_out, "IPPROTO_STCP");
      break;
    case 255:
      fprintf(proc->strace_out, "IPPROTO_RAW");
      break;
    default:
      fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d)", (int) reg->arg[2]);
      break;
    }
    break;
  case 16:
    fprintf(proc->strace_out, "PF_NETLINK, ");
    switch ((int) reg->arg[1]) {
    case 1:
      fprintf(proc->strace_out, "SOCK_STREAM, ");
      break;
    case 2:
      fprintf(proc->strace_out, "SOCK_DGRAM, ");
      break;
    case 3:
      fprintf(proc->strace_out, "SOCK_RAW, ");
      break;
    case 4:
      fprintf(proc->strace_out, "SOCK_RDM, ");
      break;
    case 5:
      fprintf(proc->strace_out, "SOCK_SEQPACKET, ");
      break;
    case 6:
      fprintf(proc->strace_out, "SOCK_DCCP, ");
      break;
    case 10:
      fprintf(proc->strace_out, "SOCK_PACKET, ");
      break;
    default:
      fprintf(proc->strace_out, "TYPE UNKNOWN (%d), ", (int) reg->arg[1]);
      break;
    }
    switch ((int) reg->arg[2]) {
    case 0:
      fprintf(proc->strace_out, "NETLINK_ROUTE");
      break;
    case 1:
      fprintf(proc->strace_out, "NETLINK_UNUSED");
      break;
    case 2:
      fprintf(proc->strace_out, "NETLINK_USERSOCK");
      break;
    case 3:
      fprintf(proc->strace_out, "NETLINK_FIREWALL");
      break;
    case 4:
      fprintf(proc->strace_out, "NETLINK_INET_DIAG");
      break;
    default:
      fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d)", (int) reg->arg[2]);
      break;
    }
    break;
  default:
    fprintf(proc->strace_out, "DOMAIN UNKNOWN (%d), ", (int) reg->arg[0]);
    break;
  }
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief print a strace-like log of getsockopt syscall */
void print_getsockopt_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out,"[%d] getsockopt(", proc->pid);
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);

  /* switch (arg->level) { */
  switch ((int) reg->arg[1]) {
  case 0:
    fprintf(proc->strace_out, "SOL_IP, ");
    switch ((int) reg->arg[2]) {
    case 1:
      fprintf(proc->strace_out, "IP_TOS, ");
      break;
    case 2:
      fprintf(proc->strace_out, "IP_TTL, ");
      break;
    case 3:
      fprintf(proc->strace_out, "IP_HDRINCL, ");
      break;
    case 4:
      fprintf(proc->strace_out, "IP_OPTIONS, ");
      break;
    case 6:
      fprintf(proc->strace_out, "IP_RECVOPTS, ");
      break;
    default:
      fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", (int) reg->arg[2]);
      break;
    }
    break;
  case 1:
    fprintf(proc->strace_out, "SOL_SOCKET, ");
    switch ((int) reg->arg[2]) {
    case 1:
      fprintf(proc->strace_out, "SO_DEBUG, ");
      break;
    case 2:
      fprintf(proc->strace_out, "SO_REUSEADDR, ");
      break;
    case 3:
      fprintf(proc->strace_out, "SO_TYPE, ");
      break;
    case 4:
      fprintf(proc->strace_out, "SO_ERROR, ");
      break;
    case 5:
      fprintf(proc->strace_out, "SO_DONTROUTE, ");
      break;
    case 6:
      fprintf(proc->strace_out, "SO_BROADCAST, ");
      break;
    case 7:
      fprintf(proc->strace_out, "SO_SNDBUF, ");
      break;
    case 8:
      fprintf(proc->strace_out, "SO_RCVBUF, ");
      break;
    case 9:
      fprintf(proc->strace_out, "SO_SNDBUFFORCE, ");
      break;
    case 10:
      fprintf(proc->strace_out, "SO_RCVBUFFORCE, ");
      break;
    case 11:
      fprintf(proc->strace_out, "SO_NO_CHECK, ");
      break;
    case 12:
      fprintf(proc->strace_out, "SO_PRIORITY, ");
      break;
    case 13:
      fprintf(proc->strace_out, "SO_LINGER, ");
      break;
    case 14:
      fprintf(proc->strace_out, "SO_BSDCOMPAT, ");
      break;
    case 15:
      fprintf(proc->strace_out, "SO_REUSEPORT, ");
      break;
    default:
      fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", (int) reg->arg[2]);
      break;
    }
    break;
  case 41:
    fprintf(proc->strace_out, "SOL_IPV6, ");
    break;
  case 58:
    fprintf(proc->strace_out, "SOL_ICMPV6, ");
    break;
  default:
    fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d), ", (int) reg->arg[1]);
    break;
  }

  fprintf(proc->strace_out, "%d ) = ", (socklen_t) reg->arg[4]);

  fprintf(proc->strace_out, "%d\n", (int) reg->ret);
}

/** @brief print a strace-like log of setsockopt syscall */
void print_setsockopt_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out,"[%d] setsockopt(", proc->pid);
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);

  switch ((int) reg->arg[1]) {
  case 0:
    fprintf(proc->strace_out, "SOL_IP, ");
    switch ((int) reg->arg[2]) {
    case 1:
      fprintf(proc->strace_out, "IP_TOS, ");
      break;
    case 2:
      fprintf(proc->strace_out, "IP_TTL, ");
      break;
    case 3:
      fprintf(proc->strace_out, "IP_HDRINCL, ");
      break;
    case 4:
      fprintf(proc->strace_out, "IP_OPTIONS, ");
      break;
    case 6:
      fprintf(proc->strace_out, "IP_RECVOPTS, ");
      break;
    default:
      fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", (int) reg->arg[2]);
      break;
    }
    break;
  case 1:
    fprintf(proc->strace_out, "SOL_SOCKET, ");
    switch ((int) reg->arg[2]) {
    case 1:
      fprintf(proc->strace_out, "SO_DEBUG, ");
      break;
    case 2:
      fprintf(proc->strace_out, "SO_REUSEADDR, ");
      break;
    case 3:
      fprintf(proc->strace_out, "SO_TYPE, ");
      break;
    case 4:
      fprintf(proc->strace_out, "SO_ERROR, ");
      break;
    case 5:
      fprintf(proc->strace_out, "SO_DONTROUTE, ");
      break;
    case 6:
      fprintf(proc->strace_out, "SO_BROADCAST, ");
      break;
    case 7:
      fprintf(proc->strace_out, "SO_SNDBUF, ");
      break;
    case 8:
      fprintf(proc->strace_out, "SO_RCVBUF, ");
      break;
    case 9:
      fprintf(proc->strace_out, "SO_SNDBUFFORCE, ");
      break;
    case 10:
      fprintf(proc->strace_out, "SO_RCVBUFFORCE, ");
      break;
    case 11:
      fprintf(proc->strace_out, "SO_NO_CHECK, ");
      break;
    case 12:
      fprintf(proc->strace_out, "SO_PRIORITY, ");
      break;
    case 13:
      fprintf(proc->strace_out, "SO_LINGER, ");
      break;
    case 14:
      fprintf(proc->strace_out, "SO_BSDCOMPAT, ");
      break;
    case 15:
      fprintf(proc->strace_out, "SO_REUSEPORT, ");
      break;
    default:
      fprintf(proc->strace_out, "OPTION UNKNOWN (%d), ", (int) reg->arg[2]);
      break;
    }
    break;
  case 41:
    fprintf(proc->strace_out, "SOL_IPV6, ");
    break;
  case 58:
    fprintf(proc->strace_out, "SOL_ICMPV6, ");
    break;
  default:
    fprintf(proc->strace_out, "PROTOCOL UNKNOWN (%d), ", (int) reg->arg[1]);
    break;
  }

  fprintf(proc->strace_out, "%d ) = ", (socklen_t) reg->arg[4]);

  fprintf(proc->strace_out, "%d\n", (int) reg->ret);
}

/** @brief print a strace-like log of listen syscall */
void print_listen_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out, "[%d] listen(", proc->pid);
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);
  fprintf(proc->strace_out, "%d ", (int) reg->arg[1]);
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief helper function to print the flags of send syscalls */
static void print_flags_send(process_descriptor_t * proc, int flags)
{
  if (flags & MSG_CONFIRM)
    fprintf(proc->strace_out, " MSG_CONFIRM |");
  if (flags & MSG_DONTROUTE)
    fprintf(proc->strace_out, " MSG_DONTROUTE |");
  if (flags & MSG_DONTWAIT)
    fprintf(proc->strace_out, " MSG_DONTWAIT |");
  if (flags & MSG_EOR)
    fprintf(proc->strace_out, " MSG_EOR |");
  if (flags & MSG_MORE)
    fprintf(proc->strace_out, " MSG_MORE |");
  if (flags & MSG_NOSIGNAL)
    fprintf(proc->strace_out, " MSG_NOSIGNAL |");
  if (flags & MSG_OOB)
    fprintf(proc->strace_out, " MSG_OOB |");
  fprintf(proc->strace_out, ", ");
}

/** @brief helper function to print the flags of recv syscalls */
static void print_flags_recv(process_descriptor_t * proc, int flags)
{
  if (flags & MSG_DONTWAIT)
    fprintf(proc->strace_out, " MSG_DONTWAIT |");
  if (flags & MSG_ERRQUEUE)
    fprintf(proc->strace_out, " MSG_ERRQUEUE |");
  if (flags & MSG_PEEK)
    fprintf(proc->strace_out, " MSG_PEEK |");
  if (flags & MSG_OOB)
    fprintf(proc->strace_out, " MSG_OOB |");
  if (flags & MSG_TRUNC)
    fprintf(proc->strace_out, " MSG_TRUNC |");
  if (flags & MSG_WAITALL)
    fprintf(proc->strace_out, " MSG_WAITALL |");
  fprintf(proc->strace_out, ", ");
}

/** @brief print a strace-like log of send syscall */
void print_send_syscall(reg_s * reg, process_descriptor_t * proc, void * data)
{
  fprintf(proc->strace_out,"[%d] sendto(", proc->pid);

#ifndef address_translation
  char buff[200];
  if ((size_t) reg->arg[2] < 200) {
    memcpy(buff, data, (size_t) reg->arg[2]);
    buff[(ssize_t) reg->ret] = '\0';
    fprintf(proc->strace_out, "%d, \"%s\" , %zu, ",(int) reg->arg[0], buff, (size_t) reg->arg[2]);
  } else {
    memcpy(buff, data, 200);
    buff[199] = '\0';
    fprintf(proc->strace_out, "%d, \"%s...\" , %zu, ", (int) reg->arg[0], buff, (size_t) reg->arg[2]);
  }
#else
  fprintf(proc->strace_out, "%d, \"%s\" , %zu, ", (int) reg->arg[0], (char *) data, (size_t) reg->arg[2]);
#endif

  if ((int) reg->arg[3] > 0) {
    print_flags_send(proc, (ssize_t) reg->arg[0]);
  } else
    fprintf(proc->strace_out, "0, ");

  fprintf(proc->strace_out, ") = %zd\n",  (ssize_t) reg->ret);
}

/** @brief print a strace-like log of recv syscall */
void print_recv_syscall(reg_s * reg, process_descriptor_t * proc, void * data)
{
  size_t len = (size_t) reg->arg[2];

  fprintf(proc->strace_out, "[%d] recvfrom(", proc->pid);
#ifndef address_translation
  if ((ssize_t) reg->ret) {
    char buff[500];
    if ((ssize_t) reg->ret <= 500) {
      memcpy(buff, data, (int) reg->ret);
      buff[(ssize_t) reg->ret] = '\0';
      fprintf(proc->strace_out, "%d, \"%s\" , %zu, ", (int) reg->arg[0], buff, len);
    } else {
      memcpy(buff, data, 500);
      buff[499] = '\0';
      fprintf(proc->strace_out, "%d, \"%s...\" , %zu, ", (int) reg->arg[0], buff, len);
    }
    if ((int) reg->arg[3] > 0)
      print_flags_send(proc, (int) reg->arg[3]);
     else
      fprintf(proc->strace_out, "0, ");
  } else
    fprintf(proc->strace_out, "%d, \"\" , %zu, ", (int) reg->arg[0], len);
#else
    fprintf(proc->strace_out, "%d, \"%s\" , %zu, ", (int) reg->arg[0], (char *) data, len);

    if ((int) reg->arg[3] > 0)
     print_flags_send(proc, (int) reg->arg[3]);
   else
       fprintf(proc->strace_out, "0, ");
#endif

  fprintf(proc->strace_out, ") = %zd\n", (ssize_t) reg->ret);
}


/** @brief print a strace-like log of sendto syscall */
void print_sendto_syscall(reg_s * reg, process_descriptor_t * proc, void * data, int is_addr, socklen_t addrlen, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  int domain = get_domain_socket(proc, (int) reg->arg[0]);

  fprintf(proc->strace_out,"[%d] sendto(", proc->pid);
 
#ifndef address_translation
  char buff[200];
  if ((size_t) reg->arg[2] < 200) {
    memcpy(buff, data, (size_t) reg->arg[2]);
    buff[(ssize_t) reg->ret] = '\0';
    fprintf(proc->strace_out, "%d, \"%s\" , %zu, ",(int) reg->arg[0], buff, (size_t) reg->arg[2]);
  } else {
    memcpy(buff, data, 200);
    buff[199] = '\0';
    fprintf(proc->strace_out, "%d, \"%s...\" , %zu, ", (int) reg->arg[0], buff, (size_t) reg->arg[2]);
  }
#else
  fprintf(proc->strace_out, "%d, \"%s\" , %zu, ", (int) reg->arg[0], (char *) data, (size_t) reg->arg[2]);
#endif

  if ((int) reg->arg[3] > 0) {
    print_flags_send(proc, (int) reg->arg[0]);
  } else
    fprintf(proc->strace_out, "0, ");

  if (domain == 2) {            // PF_INET
    if (is_addr) {
      fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(sai->sin_port),
	      inet_ntoa(sai->sin_addr));
    } else
      fprintf(proc->strace_out, "NULL, ");
  } else if (domain == 1) {     //PF_UNIX
    if (is_addr) {
      fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", sau->sun_path);
    } else
      fprintf(proc->strace_out, "NULL, ");

  } else if (domain == 16) {    //PF_NETLINK
    if (is_addr) {
      fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", snl->nl_pid, snl->nl_groups);
    } else
      fprintf(proc->strace_out, "NULL, ");
  } else {
    fprintf(proc->strace_out, "{sockaddr unknown}, ");
  }

  fprintf(proc->strace_out, "%u", addrlen);

  fprintf(proc->strace_out, ") = %zd\n",  (ssize_t) reg->ret);
}

/** @brief print a strace-like log of recvfrom syscall */
void print_recvfrom_syscall(reg_s * reg, process_descriptor_t * proc, void * data, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl, int is_addr, socklen_t addrlen)
{
  size_t len = (size_t) reg->arg[2];
  int domain = get_domain_socket(proc, (int) reg->arg[0]);

  fprintf(proc->strace_out,"[%d] recvfrom(", proc->pid);
 
#ifndef address_translation
  if ((ssize_t) reg->ret) {
    char buff[500];
    if ((ssize_t) reg->ret <= 500) {
      memcpy(buff, data, (int) reg->ret);
      buff[(ssize_t) reg->ret] = '\0';
      fprintf(proc->strace_out, "%d, \"%s\" , %zu, ", (int) reg->arg[0], buff, len);
    } else {
      memcpy(buff, data, 500);
      buff[499] = '\0';
      fprintf(proc->strace_out, "%d, \"%s...\" , %zu, ", (int) reg->arg[0], buff, len);
    }

   if ((int) reg->arg[3] > 0) {
      print_flags_send(proc, (int) reg->arg[3]);
    } else
      fprintf(proc->strace_out, "0, ");
  } else
    fprintf(proc->strace_out, "%d, \"\" , %zu, ", (int) reg->arg[0], len);
#else
    fprintf(proc->strace_out, "%d, \"%s\" , %zu, ", (int) reg->arg[0], (char *) data, len);

  if ((int) reg->arg[3] > 0) {
      print_flags_send(proc, (int) reg->arg[3]);
    } else
      fprintf(proc->strace_out, "0, ");
#endif

  if (domain == 2) {            // PF_INET
    if (is_addr) {
      fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(sai->sin_port),
	      inet_ntoa(sai->sin_addr));
    } else
      fprintf(proc->strace_out, "NULL, ");
  } else if (domain == 1) {     //PF_UNIX
    if (is_addr) {
      fprintf(proc->strace_out, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", sau->sun_path);
    } else
      fprintf(proc->strace_out, "NULL, ");

  } else if (domain == 16) {    //PF_NETLINK
    if (is_addr) {
      fprintf(proc->strace_out, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", snl->nl_pid, snl->nl_groups);
    } else
      fprintf(proc->strace_out, "NULL, ");
  } else {
    fprintf(proc->strace_out, "{sockaddr unknown}, ");
  }

  fprintf(proc->strace_out, "%u", addrlen);

  fprintf(proc->strace_out, ") = %zd\n", (ssize_t) reg->ret);
}

/** @brief print a strace-like log of sendmsg syscall */
void print_sendmsg_syscall(reg_s * reg, process_descriptor_t * proc, int len, void * data, 
			   struct msghdr * msg)
{
  fprintf(proc->strace_out,"[%d] sendmsg(", proc->pid);
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);

#ifndef address_translation
  char buff[20];
  if (len < 20) {
    memcpy(buff, data, len);
    fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, \"%s\", msg_controllen=%d, msg_flags=%d}, ",
	    (int) msg->msg_namelen, (int) msg->msg_iovlen, buff, (int) msg->msg_controllen,
	    msg->msg_flags);
  } else {
    memcpy(buff, data, 20);
    buff[19] = '\0';

    fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, \"%s...\", msg_controllen=%d, msg_flags=%d}, ",
	    (int) msg->msg_namelen, (int) msg->msg_iovlen, buff, (int) msg->msg_controllen,
	    msg->msg_flags);
  }
#else
  fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, \"%s\", msg_controllen=%d, msg_flags=%d}, ",
	  (int) msg->msg_namelen, (int) msg->msg_iovlen, (char *) data, (int) msg->msg_controllen, msg->msg_flags);
#endif

  if ((int) reg->arg[2] > 0) {
    print_flags_recv(proc, (int) reg->arg[2]);
  } else
    fprintf(proc->strace_out, "0 ");

  fprintf(proc->strace_out, ") = %zd\n", (ssize_t) reg->ret);
}

/** @brief print a strace-like log of recvmsg syscall */
void print_recvmsg_syscall(reg_s * reg, process_descriptor_t * proc, struct msghdr * msg)
{
  fprintf(proc->strace_out,"[%d] recvmsg(", proc->pid);
    
  fprintf(proc->strace_out, "%d, ", (int) reg->arg[0]);
    
  fprintf(proc->strace_out, ", {msg_namelen=%d, msg_iovlen=%d, msg_controllen=%d, msg_flags=%d}, ", (int) msg->msg_namelen,
	  (int) msg->msg_iovlen, (int) msg->msg_controllen, msg->msg_flags);
    
  if ((int) reg->arg[2] > 0) {
    print_flags_recv(proc, (int) reg->arg[2]);
  } else
    fprintf(proc->strace_out, "0 ");
    
  fprintf(proc->strace_out, ") = %zd\n", (ssize_t) reg->ret);
}

/** @brief helper function to print the events flags of poll syscall */
static void get_events_poll(process_descriptor_t * proc, short events)
{
  fprintf(proc->strace_out, "events=");
  if ((events & POLLIN) != 0)
    fprintf(proc->strace_out, "POLLIN |");
  if ((events & POLLPRI) != 0)
    fprintf(proc->strace_out, "POLLPRI |");
  if ((events & POLLOUT) != 0)
    fprintf(proc->strace_out, "POLLOUT |");
  if ((events & POLLERR) != 0)
    fprintf(proc->strace_out, "POLLERR |");
  if ((events & POLLHUP) != 0)
    fprintf(proc->strace_out, "POLLHUP |");
  if ((events & POLLNVAL) != 0)
    fprintf(proc->strace_out, "POLLNVAL |");
}

/** @brief helper function to print the revents flags of poll syscall */
static void get_revents_poll(process_descriptor_t * proc, short revents)
{
  fprintf(proc->strace_out, ", revents=");
  if ((revents & POLLIN) != 0)
    fprintf(proc->strace_out, "POLLIN |");
  if ((revents & POLLPRI) != 0)
    fprintf(proc->strace_out, "POLLPRI |");
  if ((revents & POLLOUT) != 0)
    fprintf(proc->strace_out, "POLLOUT |");
  if ((revents & POLLERR) != 0)
    fprintf(proc->strace_out, "POLLERR |");
  if ((revents & POLLHUP) != 0)
    fprintf(proc->strace_out, "POLLHUP |");
  if ((revents & POLLNVAL) != 0)
    fprintf(proc->strace_out, "POLLNVAL |");
  fprintf(proc->strace_out, "} ");
}

/** @brief helper function to print the fd, events and revents of poll syscall */
static void disp_pollfd(process_descriptor_t * proc, struct pollfd *fds, nfds_t nfds)
{
  int i;
  for (i = 0; i < nfds - 1; i++) {
    fprintf(proc->strace_out, "{fd=%d, ", fds[i].fd);
    get_events_poll(proc, fds[i].events);
    get_revents_poll(proc, fds[i].revents);
    if (i > 3) {
      fprintf(proc->strace_out, " ... }");
      break;
    }
  }
  if (nfds < 3) {
    fprintf(proc->strace_out, "{fd=%d, ", fds[nfds - 1].fd);
    get_events_poll(proc, fds[nfds - 1].events);
    get_revents_poll(proc, fds[nfds - 1].revents);
  }

}

/** @brief print a strace-like log of poll syscall */
void print_poll_syscall(reg_s * reg, process_descriptor_t * proc, struct pollfd *fd_list, int timeout)
{
  fprintf(proc->strace_out, "poll([");
  if (fd_list != NULL)
    disp_pollfd(proc, fd_list, (nfds_t) reg->arg[1]);
  else
    fprintf(proc->strace_out, "NULL");
  fprintf(proc->strace_out, " ]");
  fprintf(proc->strace_out, "%d) = %d\n",  timeout ,(int) reg->ret);
}

/** @brief helper function to print the fd of select syscall */
static void disp_selectfd(process_descriptor_t * proc, fd_set * fd)
{
  int i;
  fprintf(proc->strace_out, "[ ");
  for (i = 0; i < FD_SETSIZE; i++) {
    if (FD_ISSET(i, fd)) {
      fprintf(proc->strace_out, "%d ", i);
    }
  }
  fprintf(proc->strace_out, "]");
}

/** @brief print a strace-like log of select syscall */
void print_select_syscall(reg_s * reg, process_descriptor_t * proc, int fd_state)
{
  fprintf(proc->strace_out, "[%d] select(%d,", proc->pid, (int) reg->arg[0]);

  fd_set fd_read, fd_write, fd_exec;

  ptrace_cpy(proc->pid, &fd_read, (void *) reg->arg[1], sizeof(fd_set), "select");
  ptrace_cpy(proc->pid, &fd_write, (void *) reg->arg[2], sizeof(fd_set), "select");
  ptrace_cpy(proc->pid, &fd_exec, (void *) reg->arg[3], sizeof(fd_set), "select");

  if (fd_state & SELECT_FDRD_SET)
    disp_selectfd(proc, &fd_read);
  else
    fprintf(proc->strace_out, "NULL");
  fprintf(proc->strace_out, ", ");
  if (fd_state & SELECT_FDWR_SET)
    disp_selectfd(proc, &fd_write);
  else
    fprintf(proc->strace_out, "NULL");
  fprintf(proc->strace_out, ", ");
  if (fd_state & SELECT_FDEX_SET)
    disp_selectfd(proc, &fd_exec);
  else
    fprintf(proc->strace_out, "NULL");
  fprintf(proc->strace_out, ", ");

  struct timeval * time = (struct timeval *) reg->arg[4];
  fprintf(proc->strace_out, "%lu, %ld) = %d\n", time->tv_sec, time->tv_usec, (int) reg->ret);
}

/** @brief print a strace-like log of fcntl syscall */
void print_fcntl_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out,"[%d] fcntl( %d, ", proc->pid, (int) reg->arg[0]);
  struct flock * lock = xbt_malloc(sizeof(struct flock));

  switch ((int) reg->arg[1]) {
  case F_DUPFD:
    fprintf(proc->strace_out, "F_DUPFD");
    break;

  case F_DUPFD_CLOEXEC:
    fprintf(proc->strace_out, "F_DUPFD_CLOEXEC");
    break;

  case F_GETFD:
    fprintf(proc->strace_out, "F_GETFD");
    break;

  case F_SETFD:
    fprintf(proc->strace_out, "F_SETFD");
    if ((long) reg->arg[2]) /* cmd argument */
      fprintf(proc->strace_out, ", FD_CLOEXEC");
    else
      fprintf(proc->strace_out, ", %li", (long) reg->arg[2]);
    break;

  case F_GETFL:
    fprintf(proc->strace_out, "F_GETFL");
    break;

  case F_SETFL:
    fprintf(proc->strace_out, "F_SETFL");
    fprintf(proc->strace_out, ", %li", (long) reg->arg[2]);
    break;

  case F_SETLK:
    fprintf(proc->strace_out, "F_SETLK");
    ptrace_cpy(proc->pid, lock, (void *) reg->arg[2], sizeof(struct flock), "fcntl");
    fprintf(proc->strace_out, ", %d", lock->l_type);
    fprintf(proc->strace_out, ", %d", lock->l_whence);
    fprintf(proc->strace_out, ", %jd", lock->l_start);
    fprintf(proc->strace_out, ", %jd", lock->l_len);
    break;

  case F_SETLKW:
    fprintf(proc->strace_out, "F_SETLKW");
    ptrace_cpy(proc->pid, lock, (void *) reg->arg[2], sizeof(struct flock), "fcntl");
    fprintf(proc->strace_out, ", %d", lock->l_type);
    fprintf(proc->strace_out, ", %d", lock->l_whence);
    fprintf(proc->strace_out, ", %jd", lock->l_start);
    fprintf(proc->strace_out, ", %jd", lock->l_len);
    break;

  case F_GETLK:
    fprintf(proc->strace_out, "F_GETLK");
    ptrace_cpy(proc->pid, lock, (void *) reg->arg[2], sizeof(struct flock), "fcntl");
    fprintf(proc->strace_out, ", %d", lock->l_type);
    fprintf(proc->strace_out, ", %d", lock->l_whence);
    fprintf(proc->strace_out, ", %jd", lock->l_start);
    fprintf(proc->strace_out, ", %jd", lock->l_len);
    break;

  case F_GETOWN:
    fprintf(proc->strace_out, "F_GETOWN");
    break;

  case F_SETOWN:
    fprintf(proc->strace_out, "F_SETOWN");
    break;

  default:
    fprintf(proc->strace_out, "Unknown command");
    break;
  }
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief print a strace-like log of lseek syscall */
void print_lseek_syscall(reg_s * reg, process_descriptor_t * proc){
  fprintf(proc->strace_out, "lseek(%d, ", (int) reg->arg[0]);
  fprintf(proc->strace_out, "%d, %d)", (int) reg->arg[1], (int) reg->arg[2]);
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}

/** @brief print a strace-like log of read syscall */
void print_read_syscall(reg_s * reg, process_descriptor_t * proc)
{

  char * data = xbt_malloc0((size_t) reg->ret);
  ptrace_cpy(proc->pid, data, (void *) reg->arg[1], (size_t) reg->ret, "read");

  fprintf(proc->strace_out, "[%d] read(%d, \"%s\", %zu) = %zd\n", proc->pid, (int) reg->arg[0], data, (size_t) reg->arg[2], (ssize_t) reg->ret);
}

/** @brief print a strace-like log of write syscall */
void print_write_syscall(reg_s * reg, process_descriptor_t * proc)
{

  char * data = xbt_malloc0((size_t) reg->ret);
  ptrace_cpy(proc->pid, data, (void *) reg->arg[1], (size_t) reg->ret, "write");

  fprintf(proc->strace_out, "[%d] write(%d, \"%s\", %zu) = %zd\n", proc->pid, (int) reg->arg[0], data, (size_t) reg->arg[2], (ssize_t) reg->ret);
}

/** @brief helper function to print options of shutdown syscall */
static void print_shutdown_option(process_descriptor_t * proc, int how)
{
  switch (how) {
  case 0:
    fprintf(proc->strace_out, "SHUT_RD");
    break;
  case 1:
    fprintf(proc->strace_out, "SHUT_WR");
    break;
  case 2:
    fprintf(proc->strace_out, "SHUT_RDWR");
    break;
  }
}

/** @brief print a strace-like log of shutdown syscall */
void print_shutdown_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out, "[%d] shutdown (%d, ", proc->pid, (int) reg->arg[0]);
  print_shutdown_option(proc, (int) reg->arg[1]);
  fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
}


/** @brief print a strace-like log of getpeername syscall */
void print_getpeername_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out, "[%d] getpeername (%d, ", proc->pid, (int) reg->arg[0]);
  struct sockaddr_in *sock = xbt_malloc0(sizeof(struct sockaddr_in));
  ptrace_cpy(proc->pid, sock, (void *) reg->arg[1], sizeof(struct sockaddr_in), "getpeername");

  fprintf(proc->strace_out, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", sock->sin_port, inet_ntoa((sock->sin_addr)));
  fprintf(proc->strace_out, "%u ) = %d\n", *((socklen_t *) reg->arg[2]),  (int) reg->ret);
}

/** @brief helper function to print the flags of clone syscall */
static void print_flags_clone(process_descriptor_t * proc, int flags)
{
  if (flags & CSIGNAL)
    fprintf(proc->strace_out, " CSIGNAL |");
  if (flags & CLONE_VM)
    fprintf(proc->strace_out, " CLONE_VM |");
  if (flags & CLONE_FS)
    fprintf(proc->strace_out, " CLONE_FS |");
  if (flags & CLONE_FILES)
    fprintf(proc->strace_out, " CLONE_FILES |");
  if (flags & CLONE_SIGHAND)
    fprintf(proc->strace_out, " CLONE_SIGHAND |");
  if (flags & CLONE_PTRACE)
    fprintf(proc->strace_out, " CLONE_PTRACE |");
  if (flags & CLONE_VFORK)
    fprintf(proc->strace_out, " CLONE_VFORK |");
  if (flags & CLONE_PARENT)
    fprintf(proc->strace_out, " CLONE_PARENT |");
  if (flags & CLONE_THREAD)
    fprintf(proc->strace_out, " CLONE_THREAD |");
  if (flags & CLONE_NEWNS)
    fprintf(proc->strace_out, " CLONE_NEWNS |");
  if (flags & CLONE_SYSVSEM)
    fprintf(proc->strace_out, " CLONE_SYSVSEM |");
  if (flags & CLONE_SETTLS)
    fprintf(proc->strace_out, " CLONE_SETTLS |");
  if (flags & CLONE_PARENT_SETTID)
    fprintf(proc->strace_out, " CLONE_PARENT_SETTID |");
  if (flags & CLONE_CHILD_CLEARTID)
    fprintf(proc->strace_out, " CLONE_CHILD_CLEARTID |");
  if (flags & CLONE_DETACHED)   // unused
    fprintf(proc->strace_out, " CLONE_DETACHED |");
  if (flags & CLONE_UNTRACED)
    fprintf(proc->strace_out, " CLONE_UNTRACED |");
  if (flags & CLONE_CHILD_SETTID)
    fprintf(proc->strace_out, " CLONE_CHILD_SETTID |");
  if (flags & CLONE_NEWUTS)
    fprintf(proc->strace_out, " CLONE_NEWUTS |");
  if (flags & CLONE_NEWIPC)
    fprintf(proc->strace_out, " CLONE_NEWIPC |");
  if (flags & CLONE_NEWUSER)
    fprintf(proc->strace_out, " CLONE_NEWUSER |");
  if (flags & CLONE_NEWPID)
    fprintf(proc->strace_out, " CLONE_NEWPID |");
  if (flags & CLONE_NEWNET)
    fprintf(proc->strace_out, " CLONE_NEWNET |");
  if (flags & CLONE_IO)
    fprintf(proc->strace_out, " CLONE_IO |");
  fprintf(proc->strace_out, ", ");
}

/** @brief print a strace-like log of clone syscall */
void print_clone_syscall(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out, "[%d] clone(child_stack=%ld, flags=", proc->pid, reg->arg[1]);

  print_flags_clone(proc, reg->arg[0]);
  fprintf(proc->strace_out, "child_tidptr = %d) = %ld \n", (pid_t) reg->arg[3], (long int) reg->ret);
}

/** @brief helper function to retrieve the information of execve syscall */
static int get_string(int pid, long ptr, char *buf, int size)
{
  long data;
  char *p = (char *) &data;
  int j = 0;

  while ((data = ptrace(PTRACE_PEEKTEXT, pid, (void *) ptr, 0)) && j < size) {
    int i;
    for (i = 0; i < sizeof(data) && j < size; i++, j++) {
      if (!(buf[j] = p[i])) {
	buf[j] = '\0';
	return j;
      }
    }
    ptr += sizeof(data);
  }
  buf[j] = '\0';
  return j;
}

/** @brief print a strace-like log of execve syscall, without the return */
void print_execve_syscall_pre(reg_s * reg, process_descriptor_t * proc)
{

  pid_t pid = proc->pid;
  char bufstr[4096];
  long filename, argv;

  filename = reg->arg[0];
  fprintf(proc->strace_out, "[%d] execve(", proc->pid);
  if (filename) {
    get_string(pid, filename, bufstr, sizeof(bufstr));
    fprintf(proc->strace_out, "\"%s\", [", bufstr);
  }
  
  argv = reg->arg[1];
  int first = 1;
  for (; argv; argv += sizeof(long)) {
    filename = argv;
    /* Indirect through ptr since we have char *argv[] */
    filename = ptrace(PTRACE_PEEKTEXT, pid, (void *) filename, 0);

    if (!filename) {
      fprintf(proc->strace_out, "]");
      break;
    }

    get_string(pid, filename, bufstr, sizeof(bufstr));
    if (first) {
      fprintf(proc->strace_out, "\"%s\"", bufstr);
      first = 0;
    } else {
      fprintf(proc->strace_out, ", \"%s\"", bufstr);
    }
  }
  fprintf(proc->strace_out, ")");
}

/** @brief print the return of execve syscall */
void print_execve_syscall_post(reg_s * reg, process_descriptor_t * proc)
{
  fprintf(proc->strace_out, " = %d\n", (int) reg->ret);
}

/** @brief print open syscall */
void print_open_syscall(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;
  char bufstr[4096];
  long ptr_filename;

  ptr_filename = reg->arg[0];
  fprintf(proc->strace_out, "[%d] open(", proc->pid);
  if (ptr_filename) {
    get_string(pid, ptr_filename, bufstr, sizeof(bufstr));
    fprintf(proc->strace_out, "\"%s\"", bufstr);
  }
  if ((int) reg->arg[1]){
    fprintf(proc->strace_out,", ");
    print_flags(proc, (int) reg->arg[1] , flags_open);
  }
  if ((int) reg->ret){
    char errbuff[1024];
    strerror_r(-((int) reg->ret), errbuff, 1024);
    // The manpage says that the open syscall returns -1 while it returns -errno. Obey the manpage, at least in appearance
    fprintf(proc->strace_out, ") = -1 ");
    print_flags(proc, -((int) reg->ret), errno_values);
    fprintf(proc->strace_out," (%s)\n", strerror(-((int) reg->ret)));
  } else {
    fprintf(proc->strace_out, ") = %d\n", (int) reg->ret);
  }
}

/** @brief print creat syscall */
void print_creat_syscall(reg_s * reg, process_descriptor_t * proc){
  char * pathname = (char *) xbt_malloc(200*sizeof(char));
  
  ptrace_cpy(proc->pid, pathname, (void *) reg->arg[0], 200*sizeof(char), "creat");
  fprintf(stderr, "[%d] creat(%s, %d) = %d \n", proc->pid, pathname, (int) reg->arg[1], (int) reg->ret);
}

/** @brief print close syscall */
void print_close_syscall(reg_s * reg, process_descriptor_t * proc){
  fprintf(stderr, "[%d] close(%d) = %d \n", proc->pid, (int) reg->arg[0], (int) reg->ret);
}

/** @brief print tuxcall syscall */
void print_tuxcall_syscall(reg_s * reg, process_descriptor_t * proc){
  
  double clock;
  ptrace_cpy(proc->pid, &clock, (void *) reg->arg[1], sizeof(double), "tuxcall");
  
  fprintf(stderr, "[%d] syscall(184, %lf)\n", proc->pid, clock);
}

/* These functions are highly inspirated from the strace source code.
 * But mimicking the strace output without them is utterly difficult. */
void stprintf(process_descriptor_t * proc, const char*fmt, ...) {
  va_list args;

  va_start(args, fmt);
  if (proc->strace_out) {
    int n = vfprintf(proc->strace_out, fmt, args);
    if (n < 0) {
      if (proc->strace_out != stderr)
	perror("vfprintf failed");
    } else
      proc->curcol += n;
  }
  va_end(args);

}
static int acolumn = 40;
static const char *acolumn_spaces = "          " "          " "          " "          ";
void stprintf_tabto(process_descriptor_t * proc) {
  if (proc->curcol < acolumn)
    stprintf(proc, "%s", acolumn_spaces + proc->curcol);

}
void stprintf_eol(process_descriptor_t * proc) {
  if (proc->strace_out) {
    fprintf(proc->strace_out, "\n");
    proc->curcol = 0;
    fflush(proc->strace_out);
  }
}
