#include "task.h"
#include "simterpose.h"
#include "data_utils.h"
#include "sockets.h"
#include "communication.h"

#include "xbt/fifo.h"
#include "xbt.h"

#include <stdlib.h>
#include "xbt/log.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(TASK, simterpose, "task log");

msg_task_t create_send_communication_task(process_descriptor_t * proc_sender, struct infos_socket * is, double amount,
                                          msg_host_t sender, msg_host_t receiver)
{
  char buff[256];
  sprintf(buff, "%s send", proc_sender->name);

  msg_host_t *work_list = malloc(sizeof(msg_host_t) * 2);
  work_list[0] = sender;
  work_list[1] = receiver;

  msg_task_t task = MSG_parallel_task_create(buff, 2, work_list, 0, &amount, &(proc_sender->pid));

  task_comm_info *temp = malloc(sizeof(task_comm_info));
  temp->task = task;
  temp->sender_host = proc_sender->host;

  comm_send_data(is, temp);

  return task;
}

void send_task(msg_host_t receiver, msg_task_t task)
{
  XBT_DEBUG("Entering send_task %s", MSG_task_get_name(task));
  MSG_task_send(task, MSG_host_get_name(receiver));
}
