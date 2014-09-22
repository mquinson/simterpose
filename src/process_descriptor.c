/* process_descriptor  */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "process_descriptor.h"
#include "sockets.h"
#include "msg/msg.h"

#include <stdlib.h>

/** @brief create and initialize a new process descriptor */
process_descriptor_t *process_descriptor_new(const char *name, pid_t pid)
{
  process_descriptor_t *result = malloc(sizeof(process_descriptor_t));
  result->name = strdup(name);
  result->fd_list = malloc(sizeof(fd_descriptor_t *) * MAX_FD);
  result->pid = pid;
  result->in_syscall = 0;

  int i;
  for (i = 0; i < MAX_FD; ++i)
    result->fd_list[i] = NULL;

  // Initialize stdin, stdout, stderr
  fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
  file_desc->ref_nb = 0;
  file_desc->type = FD_STDIN;
  file_desc->proc = result;
  file_desc->fd = 0;
  file_desc->flags = 0;
  result->fd_list[0] = file_desc;
  file_desc->ref_nb++;

  file_desc = malloc(sizeof(fd_descriptor_t));
  file_desc->ref_nb = 0;
  file_desc->type = FD_STDOUT;
  file_desc->proc = result;
  file_desc->fd = 1;
  file_desc->flags = 0;
  result->fd_list[1] = file_desc;
  file_desc->ref_nb++;

  file_desc = malloc(sizeof(fd_descriptor_t));
  file_desc->ref_nb = 0;
  file_desc->type = FD_STDERR;
  file_desc->proc = result;
  file_desc->fd = 2;
  file_desc->flags = 0;
  result->fd_list[2] = file_desc;
  file_desc->ref_nb++;

  result->host = MSG_get_host_by_name(result->name);
  return result;
}

/** @brief attribute the process descriptor to the current MSG process */
void process_set_descriptor(process_descriptor_t * proc)
{
  MSG_process_set_data(MSG_process_self(), proc);
}

/** @brief free the process descriptor */
static void process_descriptor_destroy(process_descriptor_t * proc)
{
  free(proc->name);
  //We don't free each fd because application do this before TODO: check that
  int i;
  for (i = 0; i < MAX_FD; ++i) {
    if (proc->fd_list[i]) {
      proc->fd_list[i]->ref_nb--;
      free(proc->fd_list[i]);
    }
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
