#ifndef TASK_MSG_H
#define TASK_MSG_H

#include <stdlib.h>

typedef struct task_comm_info task_comm_info;

#include "sockets_msg.h"
#include "process_descriptor_msg.h"

struct task_comm_info {
  msg_task_t task;
  msg_host_t sender_host;
};

//msg_task_t create_computation_task(process_descriptor_t * proc, double amount);
//void execute_computation_task(process_descriptor_t * proc, msg_task_t task);

msg_task_t create_send_communication_task(process_descriptor_t * proc_sender, struct infos_socket *is, double amount,
                                          msg_host_t sender, msg_host_t receiver);
void send_task(msg_host_t receiver, msg_task_t task);
void receive_task(struct infos_socket *recv, process_descriptor_t * proc_receiver);

#endif
