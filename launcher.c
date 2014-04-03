#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "xbt.h"
#include "parser.h"
//#include "xbt/str.h"
//#include "xbt/dynar.h"

FILE* comm_sim;

char** get_command_line()
{
  char* buff = NULL;
  size_t length;
  getline(&buff, &length, comm_sim);
  *(strrchr(buff, '\n')) = '\0';
  xbt_dynar_t cmd_array = xbt_str_split(buff, NULL);
  char** result = (char**)xbt_dynar_to_array(cmd_array);
  return result;
}

void print_command_line(char** cmd)
{
  while(*cmd!=NULL)
  {
    printf("[%s] ", *cmd);
    ++cmd;
  }
  printf("(end of command)\n");
}

int main (int argc, char** argv)
{ 
  comm_sim = fdopen(3, "r");

  int numero;
  char* buff = NULL;
  size_t length=0;
  getline(&buff, &length, comm_sim);
  sscanf(buff, "%d", &numero);
  while(numero)
  {
    char** cmd_line = get_command_line();
//     print_command_line(cmd_line);
    if(fork() == 0)
    {
      fclose(comm_sim);
      if (execv(cmd_line[0], cmd_line)==-1) {
        fprintf(stderr, "%s : %s\n", strerror(errno), cmd_line[0]);
	exit(1);
      }
    }
    --numero;
  }
  fclose(comm_sim);
  int status;
  while(wait(&status) > 0);

  return EXIT_SUCCESS;
}
