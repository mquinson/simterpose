#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <xbt.h>
#include "parser.h"

FILE *pipe_to_simterpose;

int main(int argc, char **argv)
{
  fprintf(stderr,"Launcher starting\n");
  pipe_to_simterpose = fdopen(0, "r");

  int amount;
  char *buff = NULL;
  size_t length = 0;

  getline(&buff, &length, pipe_to_simterpose);
  sscanf(buff, "%d", &amount);
  fprintf(stderr,"launcher: %d processes to start\n",amount);

  while (amount > 0) {
    getline(&buff, &length, pipe_to_simterpose);
    *(strrchr(buff, '\n')) = '\0';
    xbt_dynar_t cmd_array = xbt_str_split(buff, NULL);
    char *display_cmd_line = xbt_str_join(cmd_array," ");
    char **cmd_line = (char **) xbt_dynar_to_array(cmd_array);
    fprintf(stderr, "launcher: Starting child: %s\n", display_cmd_line);

    if (fork() == 0) {
      fclose(pipe_to_simterpose);

      if (execv(cmd_line[0], cmd_line) == -1) {
        fprintf(stderr, "%s : %s\n", strerror(errno), cmd_line[0]);
        exit(1);
      }
    }
    --amount;
  }
  fclose(pipe_to_simterpose);
  int status;
  while (wait(&status) > 0);

  return EXIT_SUCCESS;
}
