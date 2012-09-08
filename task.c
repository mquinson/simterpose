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

//Contains all informations necessary to make receive task when happen with passing only the info_socket


void schedule_last_computation_task(pid_t pid, SD_task_t next_task, const char* name)
{
//   printf("Scheduling last computation\n");
  process_descriptor *proc = process_get_descriptor(pid);
  
  double comp_size = SD_task_get_amount(proc->last_computation_task);
  double comm_amount = 0;
  SD_workstation_t work_list = proc->station;
  
  SD_task_dependency_add(name, NULL, proc->last_computation_task, next_task);
  SD_task_schedule(proc->last_computation_task, 1, &work_list, &comp_size, &comm_amount, -1);
  proc->last_computation_task=NULL;
}


void schedule_computation_task(pid_t pid)
{
//   printf("Scheduling computation\n");
//   fprintf(stderr,"Adding compuation task to process %d\n", pid);
  process_descriptor *proc = process_get_descriptor(pid);
  double comp_size = SD_task_get_amount(proc->last_computation_task);
  double comm_amount = 0;
  SD_workstation_t work_list = proc->station;
  
  SD_task_watch(proc->last_computation_task, SD_DONE);
  
  SD_task_set_data(proc->last_computation_task, &(proc->pid));
  SD_task_schedule(proc->last_computation_task, 1, &work_list, &comp_size, &comm_amount, -1);
  proc->last_computation_task = NULL;
}



SD_task_t create_computation_task(pid_t pid, double amount)
{
//   printf("ENTERING create_computation_task\n");
  process_descriptor *proc = process_get_descriptor(pid);

  SD_task_t task = SD_task_create(/*"computation"*/NULL, NULL, amount);
  
  if(proc->last_computation_task != NULL)
    schedule_last_computation_task(pid, task, "calculation sequence");

  return task;
}

//We can factorize because receiver task are only here for scheduling
void schedule_comm_task(SD_workstation_t sender, SD_workstation_t receiver, SD_task_t task)
{
  if(SD_task_get_amount(task) < 0)
  {
    fprintf(stderr, "Scheduling a negative task comm : abort\n");
    THROW_IMPOSSIBLE;
  }
//   printf("Entering schedule_comm_task %s\n", SD_task_get_name(task));
  double* comm_amount = malloc(sizeof(double)*4);
  comm_amount[1]=SD_task_get_amount(task);
  comm_amount[2]=0.0;
  comm_amount[3]=0.0;
  comm_amount[0]=0.0;
  
  double* comp_size = malloc(sizeof(double)*2);
  comp_size[0]=0;
  comp_size[1]=0;
  
  SD_workstation_t* work_list = malloc(sizeof(SD_workstation_t)*2);
  work_list[0] = sender;
  work_list[1] = receiver;

//   fprintf(stderr, "Scheduling comm_task, %p\n", work_list);
  SD_task_schedule(task, 2, work_list, comp_size, comm_amount, -1);
  free(comp_size);
  free(comm_amount);
  free(work_list);
}



SD_task_t create_send_communication_task(pid_t pid_sender, struct infos_socket *is, double amount)
{
  process_descriptor *proc_sender = process_get_descriptor(pid_sender);
  
//   char buff[256];
//   sprintf(buff, "%s send",proc_sender->name);
  
  SD_task_t task_sending = SD_task_create(/*buff*/NULL, &(proc_sender->pid), amount);
  SD_task_watch(task_sending, SD_DONE);
  SD_task_t task_receiving = SD_task_create(/*"communication recv"*/NULL, NULL, 0);
  SD_task_watch(task_receiving, SD_DONE);
  
  task_comm_info* temp = malloc(sizeof(task_comm_info));
  temp->task = task_receiving;
  temp->sender_station = proc_sender->station;
  
  comm_send_data(is, temp);
  
  //if last_computation_task is not NULL, that means that we have to do some computation before process syscall
  if(proc_sender->last_computation_task)
    schedule_last_computation_task(pid_sender, task_sending, NULL/*"calculation"*/);

  
  SD_task_dependency_add(/*"communication"*/NULL, NULL, task_sending, task_receiving);
  
  return task_sending;
}

void task_schedule_receive(struct infos_socket* is, pid_t pid)
{
//   fprintf(stderr,"ENTERING task_schedule_receive %d\n", pid);
  
  task_comm_info* tci = comm_get_send(is);
  
  process_descriptor *proc_receiver = process_get_descriptor(pid);
  
  SD_task_set_data(tci->task, &(proc_receiver->pid));
  
  //If we have a computation task in queue, we have to scedule it before doing the other operation
  if(proc_receiver->last_computation_task)
    schedule_last_computation_task(proc_receiver->pid, tci->task,NULL /*"calculation"*/);

  schedule_comm_task(tci->sender_station, proc_receiver->station, tci->task);
  proc_receiver->on_simulation = 1;
  free(tci);
  
//   printf("Leaving task_schedule_receive\n");
}