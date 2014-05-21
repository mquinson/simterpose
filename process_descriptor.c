#include "process_descriptor.h"
#include "run_trace.h"
#include "data_utils.h"
#include "simdag/simdag.h"

#include <stdlib.h>
#include </usr/include/linux/sched.h>   /* For clone flags */


process_descriptor *process_descriptor_new(char *name, pid_t pid)
{
  process_descriptor *result = malloc(sizeof(process_descriptor));
  result->name = strdup(name);
//   char buff[256];
//   strcpy(buff, name);
//   strcat(buff, ".txt");
//   result->trace = fopen(buff, "w");
  result->fd_list = malloc(sizeof(fd_s *) * MAX_FD);
  result->pid = pid;
  result->tgid = pid;           //By default, we consider that process is the first of this pgid
  result->cpu_time = 0;
  result->idle = 0;
  result->state = 0;
  result->mediate_state = 0;
  result->last_computation_task = NULL;
  result->timeout = NULL;

  result->in_timeout = PROC_NO_TIMEOUT;
  result->scheduled = 0;
  result->idle_list = 0;
  result->on_simulation = 0;
  result->on_mediation = 0;

  int i;
  for (i = 0; i < MAX_FD; ++i)
    result->fd_list[i] = NULL;

  result->station = SD_workstation_get_by_name(result->name);

  return result;
}


void process_descriptor_destroy(process_descriptor * proc)
{
  free(proc->name);
  //We don't free each fd beacuse application do this before
  int i;
  for (i = 0; i < MAX_FD; ++i) {
    if (proc->fd_list[i])
      free(proc->fd_list[i]);
  }
  free(proc->fd_list);
  if (proc->timeout)
    free(proc->timeout);
  if (proc->last_computation_task)
    SD_task_destroy(proc->last_computation_task);
  free(proc);
}

//TODO regarder l'inline pour cette fonction
process_descriptor *process_get_descriptor(pid_t pid)
{
  return global_data->process_desc[pid];
}

void process_set_idle(process_descriptor * proc, int idle_state)
{
  proc->idle = idle_state;
}

int process_get_idle(process_descriptor * proc)
{
  return proc->idle;
}


void process_set_descriptor(pid_t pid, process_descriptor * proc)
{
  global_data->process_desc[pid] = proc;
}


int process_update_cputime(process_descriptor * proc, long long int new_cputime)
{

  int result = new_cputime - proc->cpu_time;
  proc->cpu_time = new_cputime;
  return result;
}

int process_in_syscall(process_descriptor * proc)
{
  return (proc->state & 0x1);
}

void process_set_in_syscall(process_descriptor * proc)
{
  proc->state = proc->state ^ 0x1;
}

void process_set_out_syscall(process_descriptor * proc)
{
  proc->state = proc->state ^ 0x1;
}

void process_reset_state(process_descriptor * proc)
{
  proc->state = proc->state & (~STATE_MASK);
}

//Create and set a new file descriptor
void process_fork(pid_t new_pid, pid_t pid_fork)
{
  process_descriptor *result = malloc(sizeof(process_descriptor));
  process_descriptor *forked = process_get_descriptor(pid_fork);
  result->name = strdup(forked->name);

  // result->trace = forked->trace;
  result->fd_list = malloc(sizeof(struct infos_socket *) * MAX_FD);
  result->pid = new_pid;
  result->cpu_time = 0;
  result->idle = 0;
  result->last_computation_task = NULL;
  int i;
  for (i = 0; i < MAX_FD; ++i)
    result->fd_list[i] = forked->fd_list[i];

  result->station = forked->station;

  global_data->process_desc[new_pid] = result;
}

//For detail on clone flags report to man clone
void process_clone(pid_t new_pid, pid_t pid_cloned, unsigned long flags)
{
  process_descriptor *result = malloc(sizeof(process_descriptor));
  process_descriptor *cloned = process_get_descriptor(pid_cloned);

  result->pid = new_pid;
  result->cpu_time = 0;
  result->idle = 0;
  result->last_computation_task = NULL;
  result->station = cloned->station;

  //Now we handle flags option to do the right cloning

  if (flags & CLONE_VFORK)
    THROW_UNIMPLEMENTED;

  if (flags & CLONE_THREAD)
    result->tgid = cloned->tgid;

  //if clone files flags is set, we have to share the fd_list
  if (flags & CLONE_FILES)
    result->fd_list = cloned->fd_list;
  else {
    result->fd_list = malloc(sizeof(struct infos_socket *) * MAX_FD);
    int i;
    for (i = 0; i < MAX_FD; ++i)
      result->fd_list[i] = NULL;
  }

  global_data->process_desc[new_pid] = result;
}

void process_set_state(process_descriptor * proc, int state)
{
//   printf("%x %x %x\n", proc->state, state, (state | (proc->state & 0x1)));
  proc->state = (state | (proc->state & 0x1));
//   printf("Set new state to %d : %x\n", tid, proc->state);
}

int process_get_state(process_descriptor * proc)
{
//   printf("get : %x %x %d\n", proc->state, STATE_MASK, (proc->state & STATE_MASK));
  return proc->state;
}

void process_die(pid_t pid)
{
  close_all_communication(pid);
  process_descriptor *proc = process_get_descriptor(pid);
  process_descriptor_destroy(proc);
  global_data->process_desc[pid] = NULL;
}

void process_on_simulation(process_descriptor * proc, int val)
{
  proc->on_simulation = val;
}

void process_end_mediation(process_descriptor * proc)
{
  proc->mediate_state = 0;
}

void process_on_mediation(process_descriptor * proc)
{
  proc->mediate_state = 1;
}

int process_get_free_fd(process_descriptor * proc)
{
  int i;
  for (i = 0; i < MAX_FD; ++i) {
    if (proc->fd_list[i] == NULL)
      return i;
  }
  return -1;
}
