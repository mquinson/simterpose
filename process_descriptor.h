#ifndef __TIME_PROC_H_ 
#define __TIME_PROC_H_

#define PROC_SELECT             0x00001
#define PROC_POLL               0x00002
#define PROC_CONNECT            0x00004
#define PROC_ACCEPT_IN          0x00008
#define PROC_CONNECT_DONE       0x00010

#define SELECT_FDRD_SET 0x01
#define SELECT_FDWR_SET 0x02
#define SELECT_FDEX_SET 0x04

typedef struct process_descriptor process_descriptor;
typedef struct select_arg_s select_arg_s;
typedef select_arg_s* select_arg_t;

typedef struct poll_arg_s poll_arg_s;
typedef poll_arg_s* poll_arg_t;

#include "simdag/simdag.h"
#include "sockets.h"

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

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

struct process_descriptor{
  pid_t pid;
  pid_t tgid;
  int idle;
  int syscall_in;
  long long int cpu_time;
  char* name;
  FILE* trace;
  SD_workstation_t station;
  SD_task_t last_computation_task;
  struct infos_socket** fd_list;
  
  int state;
  union{
    select_arg_s select_arg;
    poll_arg_s poll_arg;
  };
};


process_descriptor *process_descriptor_new(char* name, pid_t pid);

process_descriptor *process_get_descriptor(pid_t pid);

void process_set_descriptor(pid_t pid, process_descriptor* proc);

void process_set_idle(int pid, int idle_state);

int process_get_idle(int pid);

void process_fork(pid_t new_pid, pid_t pid_fork);

void process_exec(pid_t pid);

int process_update_cputime(pid_t pid, long long int cputime_elapsed);

long long int process_get_last_cputime(pid_t pid);

int process_in_syscall(pid_t pid);

void process_set_in_syscall(pid_t pid);

void process_set_out_syscall(pid_t pid);

void process_clone(pid_t new_pid, pid_t pid_cloned, unsigned long flags);

//store select argument and set state to SELECT
void process_set_select(pid_t pid,int fd_state,  int max, fd_set rd, fd_set wr, fd_set ex);

void process_set_poll(pid_t pid, int nbfd, struct pollfd* list);

int process_get_state(pid_t pid);

void process_set_state(pid_t tid, int state);

void* process_get_argument(pid_t pid);

struct infos_socket* process_get_fd(pid_t pid, int num);

int process_is_connect_done(pid_t pid);

void process_mark_connect_do(pid_t pid);

#endif
