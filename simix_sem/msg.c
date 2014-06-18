/* Copyright (c) 2013-2014. The SimGrid Team.
 * All rights reserved.                                                     */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU LGPL) which comes with this package. */

#include <stdio.h>
#include <stdlib.h>
#include "msg/msg.h"
#include "xbt/log.h"

XBT_LOG_NEW_DEFAULT_CATEGORY(msg_semaphore_example,
                             "Messages specific for this msg example");

int nb=5;
msg_sem_t forks[5];

static int right_handed_philosoph(int argc, char* argv[]){

  const char* name = MSG_process_get_name(MSG_process_self());
  int i = atoi(name);

  while(1) {
    XBT_INFO("Philosoph %d thinking ", i);
    MSG_process_sleep(10);

    XBT_INFO("Philosoph %d wants to eat ", i);

    XBT_INFO("Philosoph %d Trying to acquire fork %d", i, i);
    MSG_sem_acquire(forks[i]);
    XBT_INFO("Philosoph %d Acquired fork %d", i,  i);
    XBT_INFO("Philosoph %d Trying to acquire fork %d", i,  (i+1)%nb);
    MSG_sem_acquire(forks[(i+1)%nb]);
    XBT_INFO("Philosoph %d Acquired fork %d", i, (i+1)%nb);

    XBT_INFO("Philosoph %d is eating ! he's using forks n° %d and %d ", i, i, (i+1)%nb);
    MSG_process_sleep(30);

    XBT_INFO("Philosoph %d isn't hungry anymore", i);
    XBT_INFO("Philosoph %d Releasing fork %d", i,  i);
    MSG_sem_release(forks[i]);
    XBT_INFO("Philosoph %d Released fork %d", i,  i);
    XBT_INFO("Philosoph %d Releasing fork %d", i,  (i+1)%nb);
    MSG_sem_release(forks[(i+1)%nb]);
    XBT_INFO("Philosoph %d Released fork %d", i, (i+1)%nb);
  }
  return 0;
}

static int left_handed_philosoph(int argc, char* argv[]){

  const char* name = MSG_process_get_name(MSG_process_self());
  int i = atoi(name);

  while(1) {
    XBT_INFO("Philosoph %d thinking ", i);
    MSG_process_sleep(10);

    XBT_INFO("Philosoph %d wants to eat ", i);

    XBT_INFO("Philosoph %d Trying to acquire fork %d", i,  (i+1)%nb);
    MSG_sem_acquire(forks[(i+1)%nb]);
    XBT_INFO("Philosoph %d Acquired fork %d", i, (i+1)%nb);
    XBT_INFO("Philosoph %d Trying to acquire fork %d", i, i);
    MSG_sem_acquire(forks[i]);
    XBT_INFO("Philosoph %d Acquired fork %d", i,  i);

    XBT_INFO("Philosoph %d is eating ! he's using forks n° %d and %d ", i, i, (i+1)%nb);
    MSG_process_sleep(30);

    XBT_INFO("Philosoph %d Releasing fork %d", i,  (i+1)%nb);
    MSG_sem_release(forks[(i+1)%nb]);
    XBT_INFO("Philosoph %d Released fork %d", i, (i+1)%nb);
    XBT_INFO("Philosoph %d isn't hungry anymore", i);
    XBT_INFO("Philosoph %d Releasing fork %d", i,  i);
    MSG_sem_release(forks[i]);
    XBT_INFO("Philosoph %d Released fork %d", i,  i);
  }
  return 0;
}


int main(int argc, char* argv[]) {

  MSG_init(&argc, argv);
  MSG_create_environment(argv[1]);

  xbt_dynar_t hosts = MSG_hosts_as_dynar();
  msg_host_t h = xbt_dynar_get_as(hosts,0,msg_host_t);
  int i;
  for (i = 0; i < nb; i++)
    forks[i] = MSG_sem_init(1);

  for(i = 0; i<(nb-1); i++){
    char str[1];
    sprintf(str,"%d",i);
    MSG_process_create(str, right_handed_philosoph, NULL, h);
  }
 
  char str[1];
  sprintf(str,"%d", (nb-1));
  MSG_process_create(str, left_handed_philosoph, NULL, h);


  msg_error_t res = MSG_main();
  printf("Finished\n");
  return (res != MSG_OK);
}
