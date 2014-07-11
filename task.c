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
/*
static int num = 0;

msg_task_t create_computation_task(process_descriptor_t * proc, double amount)
{
  XBT_DEBUG("Creating computation task");

  num++;
  char buff[256];
  sprintf(buff, "computation %d ", num);
  msg_task_t task = MSG_parallel_task_create(buff, 1, &(proc->host), &amount, 0, NULL);

  return task;
}

void execute_computation_task(process_descriptor_t * proc, msg_task_t task)
{
  XBT_DEBUG("Executing computation");
  MSG_task_set_data(task, &(proc->pid));
  MSG_task_execute(task);
}*/


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

// called by socket
void receive_task(struct infos_socket *is, process_descriptor_t * proc_receiver)
{
  XBT_DEBUG("ENTERING receive_task");
  task_comm_info *tci = comm_get_send(is);

  MSG_task_set_data(tci->task, &(proc_receiver->pid));
  MSG_task_receive(&(tci->task), proc_receiver->name);
  free(tci);

  XBT_DEBUG("Leaving task_schedule_receive");
}
