#ifndef __TIME_PROC_H_ 
#define __TIME_PROC_H_

#define PROC_NO_STATE           0x00000
#define PROC_SELECT             0x00001
#define PROC_POLL               0x00002
#define PROC_CONNECT            0x00004
#define PROC_ACCEPT_IN          0x00008
#define PROC_CONNECT_DONE       0x00010

typedef struct process_descriptor process_descriptor;

#include "args_trace.h"
#include "simdag/simdag.h"
#include "sockets.h"
#include "run_trace.h"

#include <sys/types.h>


struct process_descriptor{
  pid_t pid;
  pid_t tgid;
  int idle;
  int syscall_in;
  long long int cpu_time;
  char* name;
  FILE* trace;
  time_desc* timeout;//point to the next timeout of process, NULL there is not timeout
  SD_workstation_t station;
  SD_task_t last_computation_task;
  struct infos_socket** fd_list;
  int in_timeout;

  
  int state;
  syscall_arg_u sysarg;
  int saved_status;
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

int process_get_state(pid_t pid);

void process_set_state(pid_t tid, int state);

struct infos_socket* process_get_fd(pid_t pid, int num);

int process_is_connect_done(pid_t pid);

void process_mark_connect_do(pid_t pid);

#endif
