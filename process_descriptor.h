#ifndef __TIME_PROC_H_ 
#define __TIME_PROC_H_

typedef struct process_descriptor process_descriptor;

#include "sysdep.h"
#include "run_trace.h"

struct process_descriptor{
  pid_t pid;
  int launch_by_launcher;
  int execve_call_before_start;
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

process_descriptor *process_descriptor_get(pid_t pid);

void process_descriptor_set(pid_t pid, process_descriptor* proc);

void process_descriptor_set_idle(int pid, int idle_state);

int process_descriptor_get_idle(int pid);

void process_descriptor_fork(pid_t new_pid, pid_t pid_fork);

void process_descriptor_exec(pid_t pid);

int update_cputime_procs(pid_t pid, long long int cputime_elapsed);

long long int get_last_cputime(pid_t pid);

int in_syscall(pid_t pid);

void set_in_syscall(pid_t pid);

void set_out_syscall(pid_t pid);

#endif
