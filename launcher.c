#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "xbt.h"
#include "surf/surfxml_parse.h"
#include "parser.h"

FILE* comm_sim;

char** get_command_line()
{
//   printf("Entering get Commandline\n");
  char* buff = NULL;
  size_t length;
  getline(&buff, &length, comm_sim);
  xbt_dynar_t cmd_array = xbt_str_split(buff, NULL);
  char** result = (char**)xbt_dynar_to_array(cmd_array);
  return result;
}

int main (int argc, char** argv)
{ 
  comm_sim = fdopen(3, "r");

  int numero=2;
  char* buff = NULL;
  size_t length=0;
//   printf("Getting line argument\n");
  getline(&buff, &length, comm_sim);
  printf("%s\n", buff);
  sscanf(buff, "%d", &numero);
  //numero =2;
  
//   printf("Process to launch : %d \n", numero);
  
  while(numero)
  {
    char** cmd_line = get_command_line();
//     printf("End get_command_line\n");
    if(fork() == 0)
    {
      fclose(comm_sim);
      printf("Commandline %s\n", cmd_line[0]);
      if (execv(cmd_line[0], cmd_line)==-1) {
	perror("execl server");
	exit(1);
      }
    }
    --numero;
  }
  fclose(comm_sim);
  
  //TODO see how to avoid non waiting son
  return EXIT_SUCCESS;
}