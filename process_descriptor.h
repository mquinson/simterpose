#ifndef __PROCESS_DESCRIPTOR_H
#define __PROCESS_DESCRIPTOR_H

#define PROC_RECVMSG            0x000200
#define PROC_READ               0x000400
#define PROC_RECVFROM           0x000800


#define PROC_NO_STATE           0x000000
#define PROC_SELECT             0x000010
#define PROC_POLL               0x000020
#define PROC_CONNECT            0x000040
#define PROC_ACCEPT		        0x000080
#define PROC_CONNECT_DONE       0x000100
#define PROC_RECV            (PROC_RECVMSG | PROC_RECVFROM | PROC_READ)

#define STATE_MASK              0x00FFF0

#define PROC_IDLE_IN_TASK       0x00100

#define PROC_NO_TIMEOUT         0
#define PROC_IN_TIMEOUT         1
#define PROC_TIMEOUT_EXPIRE     2


#define FD_STDIN                0x00
#define FD_STDOUT               0x01
#define FD_STDERR               0x02
#define FD_CLASSIC              0x04
#define FD_SOCKET               0x08
#define FD_PIPE                 0x10

#define MAX_FD 1024

#include <stdio.h>
#include <sys/types.h>
#include <msg/msg.h>

#include "syscall_data.h"

typedef struct process_descriptor process_descriptor_t;

typedef struct {
  msg_sem_t sem_client;
  msg_sem_t sem_server;
  msg_process_t client;
  msg_process_t server;
  const char *to_client;        // name of the mailbox
  const char *to_server;        // name of the mailbox
} stream_t;

typedef struct pipe_end_s pipe_end_s;
typedef pipe_end_s *pipe_end_t;

struct pipe_end_s {
  int fd;
  process_descriptor_t *proc;
};

typedef struct {
	xbt_dynar_t read_end;
	xbt_dynar_t write_end;
}pipe_t;

typedef struct {
  int type;
  process_descriptor_t *proc;
  int fd;
  stream_t *stream;
  pipe_t *pipe;
  int flags;
} fd_descriptor_t;

struct process_descriptor {
  pid_t pid;
  pid_t tgid;
  long long int cpu_time;
  char *name;
  FILE *trace;
  msg_host_t host;
  fd_descriptor_t **fd_list;

  int in_syscall;

  syscall_arg_u sysarg;
};


process_descriptor_t *process_descriptor_new(const char *name, pid_t pid);

void process_set_descriptor(process_descriptor_t * proc);

void process_fork(pid_t new_pid, process_descriptor_t * forked);

int process_update_cputime(process_descriptor_t * proc, long long int cputime_elapsed);

void process_die(process_descriptor_t * proc);

int process_get_free_fd(process_descriptor_t * proc);

#endif
