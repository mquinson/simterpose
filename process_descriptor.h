#ifndef __TIME_PROC_H_ 
#define __TIME_PROC_H_

typedef struct process_descriptor process_descriptor;

#include "simdag/simdag.h"
#include "sockets.h"

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

#endif
