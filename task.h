#ifndef INCLUDE_TASK_H
#define INCLUDE_TASK_H

#include <stdlib.h>

void create_computation_task(pid_t pid, double amount);

void create_send_communication_task(pid_t pid, double amount);

void create_recv_communication_task(pid_t pid, double amount);

#endif