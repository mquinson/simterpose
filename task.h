#ifndef INCLUDE_TASK_H
#define INCLUDE_TASK_H

#include <stdlib.h>

#include "sockets.h"

void create_computation_task(pid_t pid, double amount);

void create_send_communication_task(pid_t pid_sender, struct infos_socket *recv, double amount);

void create_recv_communication_task(struct infos_socket* recv);

#endif