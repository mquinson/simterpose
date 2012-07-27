#ifndef INCLUDE_RUN_TRACE_H
#define INCLUDE_RUN_TRACE_H

#include <sys/types.h>

#define MAX_FD 1024
#define MAX_PID 32768  

typedef struct time_desc time_desc;

#include "process_descriptor.h"
#include "xbt.h"

//For num syscall see 
//file:///usr/share/gdb/syscalls/amd64-linux.xml


typedef struct simterpose_data simterpose_data_t;
simterpose_data_t* global_data;


struct time_desc{
  pid_t pid;
  double start_time;
};


struct simterpose_data{
  xbt_dynar_t launching_time;
  process_descriptor *process_desc[MAX_PID];
  int child_amount;
  float flops_per_second;
  float micro_s_per_flop;
};

void add_to_sched_list(pid_t pid);

#endif