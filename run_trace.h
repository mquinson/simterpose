#ifndef INCLUDE_RUN_TRACE_H
#define INCLUDE_RUN_TRACE_H

#define MAX_FD 1024

#include "simdag/simdag.h"

//#define DEBUG

typedef struct simterpose_data simterpose_data_t;
simterpose_data_t* global_data;


typedef struct{
  pid_t pid;
  char* name;
  FILE* trace;
  SD_workstation_t station;
  struct infos_socket** fd_list;
}process_descriptor;


struct simterpose_data{
  int child_amount;
  pid_t launcherpid;
};
#endif