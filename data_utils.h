#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include "run_trace.h"

//automatically link with the workstation corresponding to the name
process_descriptor *process_descriptor_new(char* name, pid_t pid);

process_descriptor *process_descriptor_get(pid_t pid);

void process_descriptor_set(pid_t pid, process_descriptor* proc);

double update_simulation_clock();

void process_descriptor_set_idle(int pid, int idle_state);

int process_descriptor_get_idle(int pid);

void launch_process_idling(pid_t pid);

void process_descriptor_fork(pid_t new_pid, pid_t pid_fork);

#endif