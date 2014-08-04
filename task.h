#ifndef TASK_H
#define TASK_H

#include <stdlib.h>

typedef struct task_comm_info task_comm_info;

#include "sockets.h"
#include "process_descriptor.h"

struct task_comm_info {
  msg_task_t task;
  msg_host_t sender_host;
};



msg_task_t create_send_communication_task(process_descriptor_t * proc_sender, struct infos_socket *is, double amount,
                                          msg_host_t sender, msg_host_t receiver);

void send_task(msg_host_t receiver, msg_task_t task);

#endif
