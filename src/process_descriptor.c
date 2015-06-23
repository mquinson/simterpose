/* process_descriptor */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <stdlib.h>

#include <simgrid/msg.h>
#include "process_descriptor.h"
#include "simterpose.h"
#include "sockets.h"

static inline
void register_file_descriptor(process_descriptor_t* process, int fd, int type)
{
  fd_descriptor_t *file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
  file_desc->refcount = 0;
  file_desc->type = type;
  file_desc->proc = process;
  file_desc->fd = fd;
  file_desc->flags = 0;
  process->fd_list[fd] = file_desc;
  file_desc->refcount++;
}

/** @brief create and initialize a new process descriptor */
process_descriptor_t *process_descriptor_new(const char *name, const char *argv0, pid_t pid)
{
  process_descriptor_t *result = xbt_malloc0(sizeof(process_descriptor_t));
  result->name = xbt_strdup(name);
  result->fd_list = xbt_new0(fd_descriptor_t *, MAX_FD);
  result->pid = pid;
  result->in_syscall = 0;

  int i;
  for (i = 0; i < MAX_FD; ++i)
    result->fd_list[i] = NULL;

  // Initialize stdin, stdout, stderr
  register_file_descriptor(result, 0, FD_STDIN);
  register_file_descriptor(result, 1, FD_STDOUT);
  register_file_descriptor(result, 2, FD_STDERR);
  // TODO, handler other FDs

  result->host = MSG_get_host_by_name(result->name);

  if (strace_option) {
    char* filename = bprintf("simterpose-%s.log", argv0);

    // Take the basefile of the argv0
    char *lastsep;
    if ((lastsep = strrchr(filename,'/')))
      memmove(filename+strlen("simterpose-"), lastsep+1, filename+strlen(filename)-lastsep);

    result->strace_out = fopen(filename,"w");
    result->curcol = 0;
    xbt_assert(result->strace_out,"Cannot create file %s: %s", filename, strerror(errno));
    free(filename);
  } else {
    result->strace_out = NULL;
  }
  return result;
}

/** @brief free the process descriptor */
static void process_descriptor_destroy(process_descriptor_t * proc)
{
  free(proc->name);
  //We don't free each fd because application do this before us. TODO: check that
  int i;
  for (i = 0; i < MAX_FD; ++i) {
    if (proc->fd_list[i]) {
      proc->fd_list[i]->refcount--;
      free(proc->fd_list[i]);
    }
  }
  if (strace_option && proc->strace_out) {
    fclose(proc->strace_out);
  }
  free(proc->fd_list);
  free(proc);
}

/** @brief the process is dead, clean everything */
void process_die(process_descriptor_t * proc)
{
  close_all_communication(proc);
  process_descriptor_destroy(proc);
}
