#include "task.h"
#include "run_trace.h"
#include "data_utils.h"
#include "process_descriptor.h"
#include "sockets.h"
#include "communication.h"

#include "simdag/simdag.h"
#include "xbt/fifo.h"
#include "xbt.h"

#include <stdlib.h>
#include "xbt/log.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(TASK, ST, "task log");

//Contains all informations necessary to make receive task when happen with passing only the info_socket


void schedule_last_computation_task(pid_t pid, SD_task_t next_task, const char* name)
{
	XBT_DEBUG("Scheduling last computation task");
  process_descriptor *proc = process_get_descriptor(pid);
  
  double comp_size = SD_task_get_amount(proc->last_computation_task);
  double comm_amount = 0;
  SD_workstation_t work_list = proc->station;
  
  SD_task_dependency_add(name, NULL, proc->last_computation_task, next_task);
  SD_task_schedule(proc->last_computation_task, 1, &work_list, &comp_size, &comm_amount, -1);
  // SD_task_schedulel(proc->last_computation_task, 1, &work_list);
  proc->last_computation_task=NULL;
}

//  et comm_task
void schedule_computation_task(pid_t pid)
{
	XBT_DEBUG("Scheduling computation");
	XBT_DEBUG("Adding compuation task to process %d", pid);
  process_descriptor *proc = process_get_descriptor(pid);
  double comp_size = SD_task_get_amount(proc->last_computation_task);
  double comm_amount = 0;
  SD_workstation_t work_list = proc->station;
  
  SD_task_watch(proc->last_computation_task, SD_DONE);
  
  SD_task_set_data(proc->last_computation_task, &(proc->pid));
  SD_task_schedule(proc->last_computation_task, 1, &work_list, &comp_size, &comm_amount, -1);
  //SD_task_schedulel(proc->last_computation_task, 1, &work_list);
  proc->last_computation_task = NULL;
}

static int num=0;

// appele par calculate_computation_time qui est appele par syscall_process
SD_task_t create_computation_task(pid_t pid, double amount)
{
  XBT_DEBUG("ENTERING create_computation_task");

num++;
  char buff[256];
  sprintf(buff, "computation %d ", num);

  process_descriptor *proc = process_get_descriptor(pid);

  SD_task_t task = SD_task_create(buff, NULL, amount);
  //SD_task_t task = SD_task_create_comp_seq(buff, NULL, amount);
  
  if(proc->last_computation_task != NULL)
    schedule_last_computation_task(pid, task, "calculation sequence");

  return task;
}

//We can factorize because receiver task are only here for scheduling
// appele par process_send_call dans syscall_process, et ici dans task_schedule_receive
void schedule_comm_task(SD_workstation_t sender, SD_workstation_t receiver, SD_task_t task)
{
  if(SD_task_get_amount(task) < 0)
  {
	XBT_ERROR("Scheduling a negative task comm : abort\n");
    THROW_IMPOSSIBLE;
  }
	XBT_DEBUG("Entering schedule_comm_task %s", SD_task_get_name(task));
  double* comm_amount = malloc(sizeof(double)*4);
  comm_amount[1]=SD_task_get_amount(task);
  comm_amount[2]=0.0;
  comm_amount[3]=0.0;
  comm_amount[0]=0.0;
  
  double* comp_size = malloc(sizeof(double)*2);
  comp_size[0]=0;
  comp_size[1]=0;
  
  SD_workstation_t* work_list = malloc(sizeof(SD_workstation_t)*2); //TODO check that
  work_list[0] = sender;
  work_list[1] = receiver;
 
  XBT_DEBUG("Scheduling comm_task, %p", work_list);
  SD_task_schedule(task, 2, work_list, comp_size, comm_amount, -1);
  /* SD_task_schedulel(task, 1, work_list[0]);
  printf("toto \n");
  xbt_dynar_t children = SD_task_get_children(task);
  SD_task_t child;
  unsigned int i;
  xbt_dynar_foreach(children, i, child){
     printf("for each \n");
	SD_task_schedulel(child, 2, work_list);
      xbt_dynar_t grand_children = SD_task_get_children(child);
      SD_task_t grand_child;
      unsigned int j;
      xbt_dynar_foreach(grand_children, j, grand_child){
	printf("for each grand \n");
	SD_task_schedulel(grand_child, 1, work_list[1]);
      }
      }
      //SD_task_schedulel(task, 1, work_list[1]);*/
  free(comp_size);
  free(comm_amount);
  free(work_list);
}

// called by process_send_call dans syscall_process
SD_task_t create_send_communication_task(pid_t pid_sender, struct infos_socket *is, double amount)
{
  process_descriptor *proc_sender = process_get_descriptor(pid_sender);
  	XBT_DEBUG("Entering create_send_communication_task %s",proc_sender->name);

  char buff[256];
  sprintf(buff, "%s send",proc_sender->name);
  
  //SD_task_t task_sending = SD_task_create(buff, &(proc_sender->pid), amount);
  SD_task_t task_sending = SD_task_create_comp_seq(buff, &(proc_sender->pid), amount);
  SD_task_watch(task_sending, SD_DONE);

  SD_task_t task_transfer = SD_task_create_comm_e2e("transfert comm", NULL, amount); // transfert comm is in SD_SCHEDULABLE state


  //SD_task_t task_receiving = SD_task_create("communication recv", NULL, 0);
  SD_task_t task_receiving = SD_task_create_comp_seq("communication recv", NULL, 0); // communication recv is in SD_SCHEDULED state
  SD_task_watch(task_receiving, SD_DONE);
  
  task_comm_info* temp = malloc(sizeof(task_comm_info));
  temp->task = task_receiving;
  temp->sender_station = proc_sender->station;
  
  comm_send_data(is, temp);
  
  //if last_computation_task is not NULL, that means that we have to do some computation before process syscall
  if(proc_sender->last_computation_task)
    schedule_last_computation_task(pid_sender, task_sending, "calculation");

 // tâche de transfert entre les deux, cf tuto sur SimDag
  SD_task_dependency_add("sending-transfer", NULL, task_sending, task_transfer);  
SD_task_dependency_add("transfer-receiving", NULL, task_transfer, task_receiving);

  return task_sending;
}

// essaie de se calquer sur simgrid/examples/simdag/sd_comm_throttling.c
void create_and_schedule_communication_task(pid_t pid_sender, struct infos_socket *is, double amount, SD_workstation_t sender, SD_workstation_t receiver)
{
  process_descriptor *proc_sender = process_get_descriptor(pid_sender);
  XBT_DEBUG("Entering create_and_schedule_communication_task %s",proc_sender->name);

  char buff[256];
  sprintf(buff, "%s send",proc_sender->name);
  
  SD_task_t task_sending = SD_task_create_comp_seq(buff, &(proc_sender->pid), amount);
  SD_task_t task_transfer = SD_task_create_comm_e2e("transfert comm", NULL, amount);
  SD_task_t task_receiving = SD_task_create_comp_seq("communication recv", NULL, 0);

  SD_task_dependency_add("sending-transfer", NULL, task_sending, task_transfer);  
  SD_task_dependency_add("transfer-receiving", NULL, task_transfer, task_receiving);

  SD_task_watch(task_sending, SD_DONE);
  SD_task_watch(task_receiving, SD_DONE);
  
  task_comm_info* temp = malloc(sizeof(task_comm_info));
  temp->task = task_receiving;
  temp->sender_station = proc_sender->station;

  comm_send_data(is, temp);
  
  //if last_computation_task is not NULL, that means that we have to do some computation before process syscall
  if(proc_sender->last_computation_task)
    schedule_last_computation_task(pid_sender, task_sending, "calculation");

   if(SD_task_get_amount(task_sending) < 0)
  {
	XBT_ERROR("Scheduling a negative task comm : abort\n");
    THROW_IMPOSSIBLE;
  }
 
  SD_workstation_t* work_list = malloc(sizeof(SD_workstation_t)*2); 
  work_list[0] = sender;
  work_list[1] = receiver;
 
  XBT_DEBUG("Scheduling comm_task, %p", work_list);
  SD_task_schedulel(task_sending, 1, work_list[0]);
  SD_task_schedulel(task_receiving, 1, work_list[1]);
 
  free(work_list);
}


// called by socket
void task_schedule_receive(struct infos_socket* is, pid_t pid) 
{
	XBT_DEBUG("ENTERING task_schedule_receive %d", pid);
  
  task_comm_info* tci = comm_get_send(is);
  
  process_descriptor *proc_receiver = process_get_descriptor(pid);
  
  SD_task_set_data(tci->task, &(proc_receiver->pid));
  
  //If we have a computation task in queue, we have to scedule it before doing the other operation
  if(proc_receiver->last_computation_task)
    schedule_last_computation_task(proc_receiver->pid, tci->task,"calculation");

  schedule_comm_task(tci->sender_station, proc_receiver->station, tci->task);
  proc_receiver->on_simulation = 1;
  free(tci);
  
	XBT_DEBUG("Leaving task_schedule_receive");
}
