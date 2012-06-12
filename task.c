#include "task.h"
#include "run_trace.h"
#include "data_utils.h"
#include "sockets.h"

#include "simdag/simdag.h"
#include "xbt/fifo.h"
#include "xbt.h"

#include <stdlib.h>

//Contains all informations necessary to make receive task when happen with passing only the info_socket
typedef struct{
  SD_task_t task;
  pid_t sender_pid;
}task_comm_info;

void create_computation_task(pid_t pid, double amount)
{
  process_descriptor *proc = process_descriptor_get(pid);
  
  SD_task_t task = SD_task_create("computation", NULL, amount);
  SD_task_watch(task, SD_DONE);
  double* comp_size = malloc(sizeof(double));
  *comp_size = amount;
  SD_task_schedule(task,1,&(proc->station),comp_size,NULL,-1);
  
}

void create_send_communication_task(pid_t pid_sender, struct infos_socket *recv, double amount)
{
  process_descriptor *proc_sender = process_descriptor_get(pid_sender);
  process_descriptor *proc_receiver = recv->proc;
  
  SD_task_t task_sending = SD_task_create("communication send", NULL, amount);
  SD_task_watch(task_sending, SD_DONE);
  SD_task_t task_receiving = SD_task_create("communication recv", NULL, amount);
  SD_task_watch(task_receiving, SD_DONE);
  
  task_comm_info* temp = malloc(sizeof(task_comm_info));
  temp->task = task_receiving;
  temp->sender_pid = pid_sender;
  
  xbt_fifo_push(recv->recv_info->recv_task, temp);
  
  SD_task_dependency_add("communication", NULL, task_sending, task_receiving);
  
  double* comm_amount = malloc(sizeof(double)*4);
  comm_amount[1]=amount;
  comm_amount[2]=0.0;
  
  SD_workstation_t* work_list = malloc(sizeof(SD_workstation_t)*2);
  work_list[0] = proc_sender->station;
  work_list[1] = proc_receiver->station;
  
  SD_task_schedule(task_sending, 2, work_list, NULL, comm_amount, -1);
}

void create_recv_communication_task(struct infos_socket* recv)
{
  task_comm_info* tci = xbt_fifo_shift(recv->recv_info->recv_task);
  
  process_descriptor *proc_sender = process_descriptor_get(tci->sender_pid);
  process_descriptor *proc_receiver = recv->proc;
  
  double* comm_amount = malloc(sizeof(double)*4);
  comm_amount[2]=0.0;
  comm_amount[1]=0.0;
  
  SD_workstation_t* work_list = malloc(sizeof(SD_workstation_t)*2);
  work_list[0] = proc_sender->station;
  work_list[1] = proc_receiver->station;
  
  SD_task_schedule(tci->task, 2, work_list, NULL, comm_amount, -1);
}