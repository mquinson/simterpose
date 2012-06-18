#include "run_trace.h"
#include "data_utils.h"
#include "simdag/simdag.h"
#include "sysdep.h"

#include <string.h>

process_descriptor *process_descriptor_new(char* name, pid_t pid)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  result->name = strdup(name);
  char buff[256];
  strcpy(buff, name);
  strcat(buff, ".txt");
  result->trace = fopen(buff, "w");
  result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
  result->pid=pid;
  result->cpu_time=0;
  result->syscall_in = 0;
  result->execve_call_before_start=1;
  result->idle=0;
  int i;
  for(i=0; i<MAX_FD ; ++i)
    result->fd_list[i]=NULL;
  
  result->station = SD_workstation_get_by_name(result->name);
  
  return result;
}

//TODO regarder l'inline pour cette fonction
process_descriptor *process_descriptor_get(pid_t pid)
{
  return global_data->process_desc[pid];
}

void process_descriptor_set(pid_t pid, process_descriptor* proc)
{
  global_data->process_desc[pid]=proc;
}

double update_simulation_clock()
{
  double new_clock = SD_get_clock();
  double result = new_clock - global_data->last_clock;
  global_data->last_clock = new_clock;
  return result;
}

void process_descriptor_set_idle(int pid, int idle_state)
{
  if(idle_state && !global_data->process_desc[pid]->idle)
    ++global_data->idle_amount;
  else if (!idle_state && global_data->process_desc[pid]->idle)
    --global_data->idle_amount;
  global_data->process_desc[pid]->idle = idle_state;
}

int process_descriptor_get_idle(int pid)
{
  return global_data->process_desc[pid]->idle;
}

void launch_process_idling(pid_t pid)
{
  ++global_data->not_assigned;
  process_descriptor_set_idle(pid, 0);
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL)==-1) {
    perror("ptrace syscall");
    exit(1);
  }
}


void process_descriptor_fork(pid_t new_pid, pid_t pid_fork)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  process_descriptor* forked = process_descriptor_get(pid_fork);
  result->name = strdup(forked->name);

  result->trace = forked->trace;
  result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
  result->pid=new_pid;
  result->cpu_time=0;
  result->syscall_in = 0;
  result->execve_call_before_start=1;
  result->idle=0;
  int i;
  for(i=0; i<MAX_FD ; ++i)
    result->fd_list[i]=forked->fd_list[i];
  
  result->station = forked->station;
  
  return result;
}



