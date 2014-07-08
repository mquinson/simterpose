#include "process_descriptor_msg.h"
#include "sockets_msg.h"
#include "msg/msg.h"

#include <stdlib.h>
#include </usr/include/linux/sched.h>   /* For clone flags */


process_descriptor_t *process_descriptor_new(const char *name, pid_t pid)
{
  process_descriptor_t *result = malloc(sizeof(process_descriptor_t));
  result->name = strdup(name);
  result->fd_list = malloc(sizeof(fd_descriptor_t *) * MAX_FD);
  result->pid = pid;
  result->tgid = pid;           //By default, we consider that process is the first of this pgid
  result->cpu_time = 0;

  result->state = 0;
  result->in_syscall = 0;

  int i;
  for (i = 0; i < MAX_FD; ++i)
    result->fd_list[i] = NULL;

  // Initialize stdin, stdout, stderr
  fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
  file_desc->type = FD_STDIN;
  file_desc->proc = result;
  file_desc->fd = 0;
  result->fd_list[0] = file_desc;

  file_desc = malloc(sizeof(fd_descriptor_t));
  file_desc->type = FD_STDOUT;
  file_desc->proc = result;
  file_desc->fd = 1;
  result->fd_list[1] = file_desc;

  file_desc = malloc(sizeof(fd_descriptor_t));
  file_desc->type = FD_STDERR;
  file_desc->proc = result;
  file_desc->fd = 2;
  result->fd_list[2] = file_desc;

  result->host = MSG_get_host_by_name(result->name);
  return result;
}

void process_set_descriptor(process_descriptor_t * proc)
{
  MSG_process_set_data(MSG_process_self(), proc);
}

static void process_descriptor_destroy(process_descriptor_t * proc)
{
  free(proc->name);
  //We don't free each fd because application do this before
  int i;
  for (i = 0; i < MAX_FD; ++i) {
    if (proc->fd_list[i])
      free(proc->fd_list[i]);
  }
  free(proc->fd_list);
  free(proc);
}

int process_update_cputime(process_descriptor_t * proc, long long int new_cputime)
{
  int result = new_cputime - proc->cpu_time;
  proc->cpu_time = new_cputime;
  return result;
}

void process_reset_state(process_descriptor_t * proc)
{
  proc->state = proc->state & (~STATE_MASK);
}

/*
//Create and set a new file descriptor
void process_fork(pid_t new_pid, process_descriptor_t *forked)
{
  process_descriptor_t *result = malloc(sizeof(process_descriptor_t));
  result->name = strdup(forked->name);

  // result->trace = forked->trace;
  result->fd_list = malloc(sizeof(struct infos_socket *) * MAX_FD);
  result->pid = new_pid;
  result->cpu_time = 0;
  int i;
  for (i = 0; i < MAX_FD; ++i)
    result->fd_list[i] = forked->fd_list[i];

  process_set_descriptor(new_pid, result);
}

//For detail on clone flags report to man clone
void process_clone(pid_t new_pid, process_descriptor_t *cloned, unsigned long flags)
{
  process_descriptor_t *result = malloc(sizeof(process_descriptor_t));

  result->pid = new_pid;
  result->cpu_time = 0;

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

  process_set_descriptor(new_pid, result);
}
*/
void process_die(process_descriptor_t *proc)
{
	close_all_communication(proc);
	process_descriptor_destroy(proc);
}

int process_get_free_fd(process_descriptor_t * proc)
{
  int i;
  for (i = 0; i < MAX_FD; ++i) {
    if (proc->fd_list[i] == NULL)
      return i;
  }
  return -1;
}
