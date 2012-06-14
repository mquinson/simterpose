#ifndef INCLUDE_RUN_TRACE_H
#define INCLUDE_RUN_TRACE_H

#include <stdlib.h>

#define MAX_FD 1024
#define MAX_PID 32768  

#include "simdag/simdag.h"
#include "xbt/fifo.h"



//#define DEBUG

typedef struct simterpose_data simterpose_data_t;
simterpose_data_t* global_data;


typedef struct{
  pid_t pid;
  int execve_call_before_start;
  int idle;
  int syscall_in;
  long long int cpu_time;
  char* name;
  FILE* trace;
  SD_workstation_t station;
  SD_task_t last_computation_task;
  struct infos_socket** fd_list;
}process_descriptor;


struct simterpose_data{
  double last_clock;
  int not_assigned;
  int launcher_com;
  int process_launch;
  xbt_fifo_t time_to_next;
  pid_t last_pid_create;
  process_descriptor *process_desc[MAX_PID];
  int child_amount;
  int idle_amount;
  pid_t launcherpid;
  float flops_per_second;
  float micro_s_per_flop;
};
#endif