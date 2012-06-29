#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include <sys/types.h>

void init_global_data();

double update_simulation_clock();

pid_t pop_next_pid();

double get_next_start_time();

void add_launching_time(pid_t pid, double start_time);

void set_next_launchment(pid_t pid);

int has_sleeping_to_launch();

#endif