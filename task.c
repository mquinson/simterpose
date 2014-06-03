#include "task.h"
#include "simterpose.h"
#include "data_utils.h"
#include "sockets.h"
#include "communication.h"

#include "simdag/simdag.h"
#include "xbt/fifo.h"
#include "xbt.h"

#include <stdlib.h>
#include "xbt/log.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(TASK, SIMTERPOSE, "task log");

//Contains all informations necessary to make receive task when happen with passing only the info_socket


static void schedule_last_computation_task(process_descriptor_t *proc, SD_task_t next_task, const char *name)
{
  XBT_DEBUG("Scheduling last computation task %s", name);

  double comp_size = SD_task_get_amount(proc->last_computation_task);
  double comm_amount = 0;
  SD_workstation_t work_list = proc->host;

  SD_task_dependency_add(name, NULL, proc->last_computation_task, next_task);
  SD_task_schedule(proc->last_computation_task, 1, &work_list, &comp_size, &comm_amount, -1);
  // SD_task_schedulel(proc->last_computation_task, 1, &work_list);
  proc->last_computation_task = NULL;
}

//  et comm_task
void schedule_computation_task(process_descriptor_t *proc)
{
  XBT_DEBUG("Scheduling computation");
  //      XBT_DEBUG("Adding compuation task to process %d", pid);
  XBT_DEBUG("Adding compuation task to process");
  double comp_size = SD_task_get_amount(proc->last_computation_task);
  double comm_amount = 0;
  SD_workstation_t work_list = proc->host;

  SD_task_watch(proc->last_computation_task, SD_DONE);

  SD_task_set_data(proc->last_computation_task, &(proc->pid));
  SD_task_schedule(proc->last_computation_task, 1, &work_list, &comp_size, &comm_amount, -1);
  //SD_task_schedulel(proc->last_computation_task, 1, &work_list);
  proc->last_computation_task = NULL;
}

static int num = 0;

// appele par calculate_computation_time qui est appele par syscall_process
SD_task_t create_computation_task(process_descriptor_t *proc, double amount)
{
  XBT_DEBUG("ENTERING create_computation_task");

  num++;
  char buff[256];
  sprintf(buff, "computation %d ", num);

  SD_task_t task = SD_task_create(buff, NULL, amount);
  //SD_task_t task = SD_task_create_comp_seq(buff, NULL, amount);

  if (proc->last_computation_task != NULL)
    schedule_last_computation_task(proc, task, "calculation sequence");

  return task;
}

// essaie de se calquer sur simgrid/examples/simdag/sd_comm_throttling.c
void create_and_schedule_communication_task(process_descriptor_t *proc_sender, struct infos_socket *is, double amount,
                                            SD_workstation_t sender, SD_workstation_t receiver)
{
  XBT_DEBUG("Entering create_and_schedule_communication_task %s", proc_sender->name);

  char buff[256];
  sprintf(buff, "%s send", proc_sender->name);

  SD_task_t task_sending = SD_task_create_comp_seq(buff, &(proc_sender->pid), amount);
  SD_task_t task_transfer = SD_task_create_comm_e2e("transfert comm", NULL, amount);
  SD_task_t task_receiving = SD_task_create_comp_seq("communication recv", NULL, 0);

  SD_task_dependency_add("sending-transfer", NULL, task_sending, task_transfer);
  SD_task_dependency_add("transfer-receiving", NULL, task_transfer, task_receiving);

  SD_task_watch(task_sending, SD_DONE);
  SD_task_watch(task_receiving, SD_DONE);

  task_comm_info *temp = malloc(sizeof(task_comm_info));
  temp->task = task_receiving;
  temp->sender_host = proc_sender->host;

  comm_send_data(is, temp);

  //if last_computation_task is not NULL, that means that we have to do some computation before process syscall
  if (proc_sender->last_computation_task)
    schedule_last_computation_task(proc_sender, task_sending, "calculation");

  if (SD_task_get_amount(task_sending) < 0) {
    XBT_ERROR("Scheduling a negative task comm : abort\n");
    THROW_IMPOSSIBLE;
  }

  SD_workstation_t *work_list = malloc(sizeof(SD_workstation_t) * 2);
  work_list[0] = sender;
  work_list[1] = receiver;

  //  XBT_DEBUG("Scheduling comm_task, %p", work_list);
  XBT_DEBUG("Scheduling comm_task");
  SD_task_schedulel(task_sending, 1, work_list[0]);
  SD_task_schedulel(task_receiving, 1, work_list[1]);

  free(work_list);
}


// called by socket
void task_schedule_receive(struct infos_socket *is, pid_t pid)
{
  //    XBT_DEBUG("ENTERING task_schedule_receive %d", pid);
  XBT_DEBUG("ENTERING task_schedule_receive");

  task_comm_info *tci = comm_get_send(is);

  process_descriptor_t *proc_receiver = process_get_descriptor(pid);

  SD_task_set_data(tci->task, &(proc_receiver->pid));

  //If we have a computation task in queue, we have to scedule it before doing the other operation
  if (proc_receiver->last_computation_task)
    schedule_last_computation_task(proc_receiver, tci->task, "calculation");

  // schedule_comm_task(tci->sender_host, proc_receiver->host, tci->task);
  proc_receiver->on_simulation = 1;
  free(tci);

  XBT_DEBUG("Leaving task_schedule_receive");
}
