#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

FILE* comm_sim;

static void cmd(char *fmt, ...) {
  va_list va;
  va_start(va,fmt);
  vfprintf(comm_sim, fmt, va);
  fflush(comm_sim);
}

int main (int argc, char** argv)
{
  
  comm_sim = fdopen(3, "w");
  
  cmd("server\n");
  int pid = fork();
  if(pid==0)
  {
    if (execl("applications/server", "applications/server", NULL)==-1) {
      perror("execl server");
      exit(1);
    }
  }
  
  
  sleep(3);
  
  
  cmd("client\n");
  pid = fork();
  
  if(pid==0)
  {
    if (execl("applications/client", "applications/client", NULL)==-1) {
      perror("execl client");
      exit(1);
    }
  }
  
  
  return EXIT_SUCCESS;
}