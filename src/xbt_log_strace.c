/* strace_appender - a fancy log appender for the SimGrid logging
 *                   mechanism that sends the output to the
 *                   strace-like files */

/* Copyright (c) 2007-2015. The SimGrid Team.  All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU LGPL) which comes with this package. */

#ifdef new_version
#include <simgrid/msg.h>
#else
#include <msg/msg.h>
#endif

#include <xbt.h>

#include "print_syscall.h"
#include "process_descriptor.h"

//#include "xbt/log_private.h" // Oops, sorry for violating your intimacy this way
struct xbt_log_appender_s {    // Yeah, I know. Sorry.
  void (*do_append) (xbt_log_appender_t this_appender, char *event);
  void (*free_) (xbt_log_appender_t this_);
  void *data;
};


static void append_file(xbt_log_appender_t this_, char *str) {
  process_descriptor_t *proc = NULL;
  msg_process_t myself = MSG_process_self();
  if (myself != NULL) { // We are in a user process
    proc = MSG_process_get_data(myself);
  }
  if (proc && proc->strace_out) {
    fputs(str, proc->strace_out);
  }
  fputs(str, (FILE *) this_->data);
}

static void free_(xbt_log_appender_t this_) {
  if (this_->data != stderr)
    fclose(this_->data);
}

xbt_log_appender_t xbt_log_appender_strace_new(void) {

  xbt_log_appender_t res = xbt_new0(s_xbt_log_appender_t, 1);
  res->do_append = append_file;
  res->free_ = free_;
  res->data = (void *) stderr;
  return res;
}
