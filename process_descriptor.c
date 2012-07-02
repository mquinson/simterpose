#include "process_descriptor.h"
#include "run_trace.h"
#include "data_utils.h"
#include "simdag/simdag.h"

#include <stdlib.h>
#include <sched.h> /* For clone flags*/


process_descriptor *process_descriptor_new(char* name, pid_t pid)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  result->name = strdup(name);
//   char buff[256];
//   strcpy(buff, name);
//   strcat(buff, ".txt");
//   result->trace = fopen(buff, "w");
  result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
  result->pid=pid;
  result->pid = pid; //By default, we consider that process is the first of this pgid
  result->cpu_time=0; 
  result->syscall_in = 0;
  result->idle=0;
  result->state = 0;
  result->last_computation_task = NULL;
  int i;
  for(i=0; i<MAX_FD ; ++i)
    result->fd_list[i]=NULL;
  
  result->station = SD_workstation_get_by_name(result->name);
  
  return result;
}

//TODO regarder l'inline pour cette fonction
process_descriptor *process_get_descriptor(pid_t pid)
{
  return global_data->process_desc[pid];
}

void process_set_idle(int pid, int idle_state)
{
  global_data->process_desc[pid]->idle = idle_state;
}

int process_get_idle(int pid)
{
  return global_data->process_desc[pid]->idle;
}


void process_set_descriptor(pid_t pid, process_descriptor* proc)
{
  global_data->process_desc[pid]=proc;
}


int process_update_cputime(pid_t pid, long long int new_cputime) {
  
  process_descriptor *proc = process_get_descriptor(pid);
  int result = new_cputime - proc->cpu_time;
  proc->cpu_time = new_cputime;
  return result;
}


long long int process_get_last_cputime(pid_t pid) {
  process_descriptor *proc = process_get_descriptor(pid);
  return proc->cpu_time;
}

int process_in_syscall(pid_t pid) {
  process_descriptor *proc = process_get_descriptor(pid);
  return proc->syscall_in;
}

void process_set_in_syscall(pid_t pid) {
  process_descriptor *proc = process_get_descriptor(pid);
  proc->syscall_in=1;
}

void process_set_out_syscall(pid_t pid) {
  process_descriptor *proc = process_get_descriptor(pid);
  proc->syscall_in=0;
}

//Create and set a new file descriptor
void process_fork(pid_t new_pid, pid_t pid_fork)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  process_descriptor* forked = process_get_descriptor(pid_fork);
  result->name = strdup(forked->name);
  
  result->trace = forked->trace;
  result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
  result->pid=new_pid;
  result->cpu_time=0;
  result->syscall_in = 0;
  result->idle=0;
  result->last_computation_task = NULL;
  int i;
  for(i=0; i<MAX_FD ; ++i)
    result->fd_list[i]=forked->fd_list[i];
  
  result->station = forked->station;
  
  global_data->process_desc[new_pid] = result;
}

//For detail on clone flags report to man clone
void process_clone(pid_t new_pid, pid_t pid_cloned, unsigned long flags)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  process_descriptor* cloned = process_get_descriptor(pid_cloned);
  
  result->pid=new_pid;
  result->cpu_time=0;
  result->syscall_in = 0;
  result->idle=0;
  result->last_computation_task = NULL;
  result->station = cloned->station;
  
  //Now we handle flags option to do the right cloning
  
  if(flags & CLONE_VFORK)
    THROW_UNIMPLEMENTED;
  
  if(flags & CLONE_THREAD)
    result->tgid = cloned->tgid;

  //if clone files flags is set, we have to share the fd_list
  if(flags & CLONE_FILES)
    result->fd_list = cloned->fd_list;
  else
  {
    result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
    int i;
    for(i=0; i<MAX_FD ; ++i)
      result->fd_list[i]=NULL;
  }
  
  global_data->process_desc[new_pid] = result;
}


void process_exec(pid_t pid)
{
  //TODO add mecanism to socket to know when close them on exec (witho SOCK_CLOEXEC on type)
  //   for(i=0; i<MAX_FD ; ++i)
  //     result->fd_list[i]=NULL;
}

void process_set_select(pid_t pid, int max, fd_set rd, fd_set wr, fd_set ex)
{
  process_descriptor* proc = process_get_descriptor(pid);
  proc->state = PROC_SELECT;
  proc->select_arg.maxfd = max;
  proc->select_arg.fd_read = rd;
  proc->select_arg.fd_write = wr;
  proc->select_arg.fd_except = ex;
}

void process_set_poll(pid_t pid, int nbfd, struct pollfd* list)
{
  process_descriptor* proc = process_get_descriptor(pid);
  proc->state = PROC_POLL;
  proc->poll_arg.nbfd = nbfd;
  proc->poll_arg.fd_list = list;
}

