/* ptrace -- Helpers functions to not call ptrace manually */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */


#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
  unsigned long reg_orig;
  unsigned long ret;
  unsigned long arg[6];
} reg_s;

extern const char *syscall_list[];

void ptrace_cpy(pid_t child, void *dst, void *src, size_t len, const char *syscall);

void ptrace_poke(pid_t pid, void *dst, void *src, size_t len);

void ptrace_resume_process(const pid_t pid);

void ptrace_detach_process(const pid_t pid);

void ptrace_get_register(const pid_t pid, reg_s * arg);

int ptrace_get_pid_clone(const pid_t pid);

void ptrace_rewind_syscalls(const pid_t pid);

void ptrace_neutralize_syscall(const pid_t pid);

void ptrace_restore_syscall(pid_t pid, unsigned long syscall, unsigned long result);

//Call this when you are in syscall
int ptrace_record_socket(pid_t pid);

int ptrace_find_free_binding_port(const pid_t pid);

#endif                          /* PTRACE_H */
