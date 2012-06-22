#ifndef INCLUDE_TASK_H
#define INCLUDE_TASK_H

#include <stdlib.h>

#include "sockets.h"
#include "simdag/simdag.h"

void create_computation_task(pid_t pid, double amount);

SD_task_t create_send_communication_task(pid_t pid_sender, struct infos_socket *recv, double amount);

void task_schedule_receive(struct infos_socket* recv);

void schedule_comm_task(SD_workstation_t sender, SD_workstation_t receiver, SD_task_t task);

#endif