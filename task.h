#ifndef INCLUDE_TASK_H
#define INCLUDE_TASK_H

#include <stdlib.h>

typedef struct task_comm_info task_comm_info;

#include "sockets.h"
#include "simdag/simdag.h"

struct task_comm_info{ 
  SD_task_t task;
  SD_workstation_t sender_station;
};


SD_task_t create_computation_task(pid_t pid, double amount);

void schedule_computation_task(pid_t pid);

SD_task_t create_send_communication_task(pid_t pid_sender, struct infos_socket *recv, double amount);

void task_schedule_receive(struct infos_socket* recv, pid_t pid);

void schedule_comm_task(SD_workstation_t sender, SD_workstation_t receiver, SD_task_t task);

#endif