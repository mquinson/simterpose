#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include <sys/types.h>

void init_global_data();

double update_simulation_clock();

void launch_process_idling(pid_t pid);

pid_t pop_next_pid();

double get_next_start_time();

void add_launching_time(pid_t pid, double start_time);

#endif