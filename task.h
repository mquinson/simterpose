#ifndef INCLUDE_TASK_H
#define INCLUDE_TASK_H

#include <stdlib.h>

typedef struct task_comm_info task_comm_info;

#include "sockets.h"
#include "simdag/simdag.h"
#include "process_descriptor.h"

struct task_comm_info {
  SD_task_t task;
  SD_workstation_t sender_host;
};


SD_task_t create_computation_task(process_descriptor_t * proc, double amount);

void schedule_computation_task(process_descriptor_t * proc);

void task_schedule_receive(struct infos_socket *recv, pid_t pid);

void create_and_schedule_communication_task(process_descriptor_t * proc_sender, struct infos_socket *is, double amount,
                                            SD_workstation_t sender, SD_workstation_t receiver);

#endif
