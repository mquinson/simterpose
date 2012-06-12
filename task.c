#include "task.h"
#include "run_trace.h"
#include "data_utils.h"

#include "simdag/simdag.h"

#include <stdlib.h>

void create_computation_task(pid_t pid, double amount)
{
  process_descriptor *proc = process_descriptor_get(pid);
  
  SD_task_t task = SD_task_create("computation", NULL, amount);
}

void create_send_communication_task(pid_t pid, double amount)
{
  process_descriptor *proc = process_descriptor_get(pid);
  
  SD_task_t task = SD_task_create_comm_e2e("communication send", NULL, amount);
}

void create_recv_communication_task(pid_t pid, double amount)
{
  process_descriptor *proc = process_descriptor_get(pid);
  
  SD_task_t task = SD_task_create_comm_e2e("communication recv", NULL, amount);
}