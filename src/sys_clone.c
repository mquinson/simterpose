/* sys_clone -- Handles clone syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <linux/sched.h>   /* For clone flags */

#include <xbt.h>

#include "sys_clone.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

static int clone_number = 0;

/** @brief handles clone syscall at the entrance ant the exit
 *  At the exit of the syscall, we can be either in the parent or the clone.
 * If we are in the clone we actually create a new MSG process which inherits the file descriptors from the parent.
 */
void syscall_clone(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc) {

  // We must distinguish from syscall-stops (in ancestor/caller) and PTRACE_EVENT (in new process).

  int ret = reg->ret;

  unsigned int signal = WSTOPSIG(proc->status);
  if (signal & (SIGTRAP | 0x80)) { // Regular syscall-stop
    fprintf(stderr,"Regular syscall-stop, it seems\n");
    // we are in the parent
    if (proc_entering(proc)) {
      proc_inside(proc);
      /* nothing to do at entrance */
    } else {
      proc_outside(proc);


      int pid_clone = ptrace_get_pid_clone(proc->pid);
      XBT_DEBUG("clone returning in parent, ret = %d, pid_clone = %d", ret, pid_clone);


    }
  } else if (proc_event_exec(proc)) {
    XBT_DEBUG("In child of clone");

    int pid_clone = ptrace_get_pid_clone(proc->pid);
    XBT_DEBUG("clone returning in child, ret = %d, pid_clone = %d", ret, pid_clone);
    proc_outside(proc);

    get_args_clone(proc, reg, sysarg);
    clone_arg_t arg = &(sysarg->clone);

    process_descriptor_t *clone = process_descriptor_new(proc->name, bprintf("cloned_%d",pid_clone), pid_clone);

    // the clone inherits the fd_list but subsequent actions on fd
    // do NOT affect the parent unless CLONE_FILES is set
    xbt_dict_cursor_t cursor = NULL;
    char *key;
    fd_descriptor_t* file_desc;
    xbt_dict_foreach(proc->fd_map, cursor, key, file_desc) {
      int i = *(int*) key;
      if (!file_desc)
        continue;

      fd_descriptor_t* clone_desc = xbt_malloc0(sizeof(fd_descriptor_t));
      process_descriptor_set_fd(clone, i, clone_desc);
      clone_desc->proc = clone;
      clone_desc->refcount = 0;
      if (file_desc != NULL) {
        clone_desc->fd = file_desc->fd;
        clone_desc->flags = file_desc->flags;
        clone_desc->pipe = file_desc->pipe;
        clone_desc->stream = file_desc->stream;
        clone_desc->type = file_desc->type;
      }
      // deal with pipes
      if (clone_desc->type == FD_PIPE) {
        pipe_t *pipe = clone_desc->pipe;
        xbt_assert(pipe != NULL);

        // copy all the fds in the read end of the pipe
        unsigned int cpt_in;
        pipe_end_t end_in;
        xbt_dynar_t read_end = pipe->read_end;
        xbt_dynar_foreach(read_end, cpt_in, end_in) {
          // we have to make sure we don't add endlessly the fd from the clone
          //TODO we still add pipes twice sometimes
          if (end_in->proc != clone && end_in->proc->pid != clone->pid) {
            xbt_assert(end_in != NULL);
            pipe_end_t clone_end = xbt_malloc0(sizeof(pipe_end_s));
            clone_end->fd = end_in->fd;
            clone_end->proc = clone;
            xbt_dynar_push(read_end, &clone_end);
          }
        }

        // copy all the fds in the write end of the pipe
        xbt_dynar_t write_end = pipe->write_end;
        unsigned int cpt_out;
        pipe_end_t end_out;
        xbt_dynar_foreach(write_end, cpt_out, end_out) {
          // we have to make sure we don't add endlessly the fd from the clone
          if (end_out->proc != clone && end_out->proc->pid != clone->pid) {
            xbt_assert(end_out != NULL);
            pipe_end_t clone_end = xbt_malloc0(sizeof(pipe_end_s));
            clone_end->fd = end_out->fd;
            clone_end->proc = clone;
            xbt_dynar_push(write_end, &clone_end);
          }
        }

      }
    }

    unsigned long flags = arg->clone_flags;

    //if (flags & CLONE_VM) // Nothing to do: we don't care if they share the memory
    //if (flags & CLONE_FS) // Nothing to do: we don't care if they share the file system
    if (flags & CLONE_FILES)
      XBT_WARN("CLONE_FILES unhandled");
    if (flags & CLONE_SIGHAND)
      XBT_WARN("CLONE_SIGHAND unhandled");
    if (flags & CLONE_PTRACE)
      XBT_WARN("CLONE_PTRACE ignored");
    if (flags & CLONE_VFORK)
      XBT_WARN("CLONE_VFORK unhandled");
    if (flags & CLONE_PARENT)
      XBT_WARN("CLONE_PARENT unhandled");
    if (flags & CLONE_THREAD)
      XBT_WARN("CLONE_THREAD unhandled");
    if (flags & CLONE_NEWNS)
      XBT_WARN("CLONE_NEWNS unhandled");
    if (flags & CLONE_SYSVSEM)
      XBT_WARN("CLONE_SYSVSEM unhandled");
    if (flags & CLONE_SETTLS)
      XBT_WARN("CLONE_SETTLS unhandled");
    if (flags & CLONE_UNTRACED)
      XBT_WARN("CLONE_UNTRACED unhandled");
    if (flags & CLONE_NEWUTS)
      XBT_WARN("CLONE_NEWUTS unhandled");
    if (flags & CLONE_NEWIPC)
      XBT_WARN("CLONE_NEWIPC unhandled");
    if (flags & CLONE_NEWUSER)
      XBT_WARN("CLONE_NEWUSER unhandled");
    if (flags & CLONE_NEWPID)
      XBT_WARN("CLONE_NEWPID unhandled");
    if (flags & CLONE_NEWNET)
      XBT_WARN("CLONE_NEWNET unhandled");
    if (flags & CLONE_IO)
      XBT_WARN("CLONE_IO unhandled");
    if (flags & CLONE_PARENT_SETTID)
      XBT_WARN("CLONE_PARENT_SETTID unhandled");
    if (flags & CLONE_CHILD_CLEARTID)
      XBT_WARN("CLONE_CHILD_CLEARTID unhandled");
    if (flags & CLONE_CHILD_SETTID)
      XBT_WARN("CLONE_CHILD_SETTID unhandled");

    arg->ret = clone->pid;
    ptrace_restore_syscall(proc->pid, SYS_clone, arg->ret);

    if (strace_option)
      print_clone_syscall(proc, sysarg);

    char name[256];
    sprintf(name, "clone #%d of %s", ++clone_number, MSG_process_get_name(MSG_process_self()));
    XBT_DEBUG("Creating %s, pid = %d", name, clone->pid);
    // TODO: the current MSG process should not continue past that point:
    //        the clone is started, current can go back to its own considerations.
    // but maybe we want to start the clone in a different manner?
    MSG_process_create(name, main_loop, clone, MSG_host_self());
    proc_inside(proc);
  } else {
    fprintf(stderr,"No idea why I'm here after cloning (not in a syscall-stop nor in a clone event)\n");
  }
}
