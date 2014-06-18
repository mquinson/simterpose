/* Copyright (c) 2013-2014. The SimGrid Team.
 * All rights reserved.                                                     */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU LGPL) which comes with this package. */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "msg/msg.h"
#include "simgrid/simix.h" // for semaphors
#include "xbt/log.h"

XBT_LOG_NEW_DEFAULT_CATEGORY(simix_semaphore_example2,
                             "Messages specific for this simix example");

smx_sem_t conn;
smx_sem_t acc;

static int connect(int argc, char* argv[]){

    XBT_INFO("Coucou je suis connect!");
    XBT_INFO("connect: j'essaie de prendre connect");
    simcall_sem_acquire(conn);
    XBT_INFO("connect: connec pris! je libère accept");
    simcall_sem_release(acc);
    XBT_INFO("connect: accept libéré");

  return 0;
}

static int accept(int argc, char* argv[]){

    XBT_INFO("Coucou je suis accept!, je vais dormir 10'");
    MSG_process_sleep(10);

    XBT_INFO("accept: je libère connect");
    simcall_sem_release(conn);
    XBT_INFO("accept: j'essaie de prendre accept");
    simcall_sem_acquire(acc);
    XBT_INFO("accept: accept pris!");

  return 0;
}



int main(int argc, char* argv[]) {

  MSG_init(&argc, argv);
  MSG_create_environment(argv[1]);

  xbt_dynar_t hosts = MSG_hosts_as_dynar();
  msg_host_t h = xbt_dynar_get_as(hosts,0,msg_host_t);
  conn  = simcall_sem_init(0); 
  acc  = simcall_sem_init(0); 


  MSG_process_create("connect", connect, NULL, h);
  MSG_process_create("accept", accept, NULL, h);

  msg_error_t res = MSG_main();
  printf("Finished\n");
  return (res != MSG_OK);
}
