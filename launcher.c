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
  getline(&buff, &length, comm_sim);
  sscanf(buff, "%d", &numero);
  
  while(numero)
  {
    char** cmd_line = get_command_line();
    if(fork() == 0)
    {
      fclose(comm_sim);
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