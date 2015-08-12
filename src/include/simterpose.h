/* simterpose -- Main configurations of Simterpose */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef SIMTERPOSE_H
#define SIMTERPOSE_H

// Runtime options
extern int strace_option; // whether we should display strace-like outputs


#define address_translation
#define arch_64

#include <sys/types.h>
#include <xbt.h>

#include "process_descriptor.h"

#define MAX_PID 32768

#define PORT_BIND       0x1
#define PORT_LOCAL      0x2
#define PORT_REMOTE     0x4
#define ABORT(error) do {printf(error); abort();} while(0)

typedef struct simterpose_host simterpose_host_t;
typedef struct port_desc port_desc_t;
typedef struct translate_desc translate_desc_t;

//For num syscall see
//file:///usr/share/gdb/syscalls/amd64-linux.xml

struct port_desc {
  int port_num;
  int real_port;
  int option;
  int amount_socket;
  struct infos_socket *bind_socket;
};

struct translate_desc {
  int port_num;
  unsigned int ip;
};

struct simterpose_host {
  unsigned int ip;
  xbt_dict_t port;
};

int simterpose_process_runner(int argc, char *argv[]);
int main_loop(int argc, char *argv[]);

#endif
