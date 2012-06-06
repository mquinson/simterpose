#include <stdio.h>
#include <stdlib.h>
#include "msg/msg.h"
#include "xbt.h"                /* calloc, printf */
#include "xbt/log.h"

typedef struct  {
  int last_Irecv_sender_id;
  int bcast_counter;
  int reduce_counter;
  int allReduce_counter;
  xbt_dynar_t isends; /* of msg_comm_t */
  /* Used to implement irecv+wait */
  xbt_dynar_t irecvs; /* of msg_comm_t */
  xbt_dynar_t tasks; /* of m_task_t */
} s_process_globals_t, *process_globals_t;


static double parse_double(const char *string)
{
  double value=0;
  char *endptr;
  
  value = strtod(string, &endptr);
  if (*endptr != '\0')
    THROWF(unknown_error, 0, "%s is not a double", string);
  return value;
}

static void asynchronous_cleanup(void) {
  process_globals_t globals = (process_globals_t) MSG_process_get_data(MSG_process_self());
  
  /* Destroy any isend which correspond to completed communications */
  int found;
  msg_comm_t comm;
  while ((found = MSG_comm_testany(globals->isends)) != -1) {
    xbt_dynar_remove_at(globals->isends,found,&comm);
    MSG_comm_destroy(comm);
  }
}

static void action_init(const char *const *action)
{ 
  process_globals_t globals = (process_globals_t) calloc(1, sizeof(s_process_globals_t));
  globals->isends = xbt_dynar_new(sizeof(msg_comm_t),NULL);
  globals->irecvs = xbt_dynar_new(sizeof(msg_comm_t),NULL);
  globals->tasks  = xbt_dynar_new(sizeof(m_task_t),NULL);
  MSG_process_set_data(MSG_process_self(),globals);
}



static void action_recv(const char *const *action)
{
  
  printf("Entering receiving\n");
  char *name = "client recv server";
  char mailbox_name[250];
  //const char *size_str = action[3];
  //double size=parse_double(action[3]);
  m_task_t task = NULL;//MSG_task_create(name, 0, size, NULL);
  //double clock = MSG_get_clock();
  
  sprintf(mailbox_name, "%s:%s:%s_%s:%s:%s", action[2],action[6], action[7],  MSG_process_get_name(MSG_process_self()), action[4], action[5]);
  //printf(" recv mailbox : %s\n", mailbox_name);
  
  MSG_error_t res = MSG_task_receive(&task, mailbox_name);
  
  asynchronous_cleanup();
}

static void action_compute(const char *const *action)
{
  char *name = NULL;
  const char *amout = action[2];
  m_task_t task = MSG_task_create(name, parse_double(amout), 0, NULL);
  //double clock = MSG_get_clock();
  
  MSG_task_execute(task);
  MSG_task_destroy(task);

  free(name);
}

static void action_send(const char *const *action)
{
  char to[250];
  char *name = strdup("server send client");
//   printf("Entering send\n", action[0], action[1]);
  sprintf(to, "%s:%s:%s_%s:%s:%s", MSG_process_get_name(MSG_process_self()), action[4], action[5] ,action[2],action[6], action[7]);
  
  //printf("sendto mailbox : %s\n", to);
  
  //const char *size_str = action[3];
  double size=parse_double(action[3]);
  //double clock = MSG_get_clock(); /* this "call" is free thanks to inlining */
  
  //   if (XBT_LOG_ISENABLED(actions, xbt_log_priority_verbose))
  //     name = xbt_str_join_array(action, " ");
  
  MSG_task_send(MSG_task_create(name, 0, size, NULL), to);
//   printf("End of sending : %lf %lf\n", parse_double(action[3]), MSG_get_clock()-clock);
  
  asynchronous_cleanup();
}

static void action_finalize(const char *const *action)
{
  process_globals_t globals = (process_globals_t) MSG_process_get_data(MSG_process_self());
  if (globals){
    xbt_dynar_free_container(&(globals->isends));
    xbt_dynar_free_container(&(globals->irecvs));
    xbt_dynar_free_container(&(globals->tasks));
    free(globals);
  }
}

void init_replay (int argc, char** argv)
{
  MSG_global_init(&argc, argv);
  MSG_create_environment(argv[1]);
  MSG_launch_application(argv[2]);
  
  MSG_action_register("init", action_init);
  MSG_action_register("recv", action_recv);
  MSG_action_register("send", action_send);
  MSG_action_register("compute", action_compute);
  MSG_action_register("exit_group", action_finalize);
}