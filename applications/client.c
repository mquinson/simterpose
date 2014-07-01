#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define SERV_PORT 2227

//#define BUFFER_SIZE 1000

#define IP "162.32.43.1"
//#define IP "127.0.0.1"

int main(int argc, char **argv)
{

  if (argc < 3) {
    fprintf(stderr, "usage: %s amount_of_messages message_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int msg_count = atoi(argv[1]);
  int message_size = atoi(argv[2]);

  struct timespec tvcl;
  clock_gettime(NULL, &tvcl);
  fprintf(stderr, "Client starting: #msg: %d; size: %d (time: %d; clock_gettime: %f)\n",
          msg_count, message_size, time(NULL), tvcl.tv_sec + tvcl.tv_nsec / 1000000000.0);


  int clientSocket;
  u_short port;
  int res;
  char *buff = malloc(message_size);
  char *expected = malloc(message_size);
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;

  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Client: error while creating the real socket");
    exit(1);
  }
  struct sockaddr_in cli_addr;
  memset(&cli_addr, 0, sizeof(struct sockaddr_in));
  host_addr = inet_addr(IP);
  serverHostEnt = gethostbyname(IP);
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  port = SERV_PORT;
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);

  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    fprintf(stderr, "Client: Cannot connect to server: %s\n", strerror(errno));
    exit(1);
  }

  int msg_number = 0;

  for (msg_number = 0; msg_number < msg_count; ++msg_number) {
    sprintf(buff, "This is the message #%d produced on the client.", msg_number);
    res = send(clientSocket, buff, message_size, 0);
    if (res == -1) {
      perror("Client: cannot send message");
      exit(1);
    }
    fprintf(stderr, "Client: sent message #%d\n", msg_number);

    int length = message_size;
    while (length > 0) {
      res = recv(clientSocket, buff, length, 0);
      if (res == -1) {
        fprintf(stderr, "Client: Error while sending message #%d: %s\n", msg_number, strerror(errno));
        exit(1);
      }
      length -= res;
    }
    sprintf(expected, "This is the answer #%d, from the server.", msg_number);
    if (strcmp(buff, expected)) {
      fprintf(stderr, "Client: received answer does not match at step %d (got: %s)\n", msg_number, buff);
      exit(1);
    }
    fprintf(stderr, "Client: reception of answer #%d was successful\n", msg_number);
  }
  shutdown(clientSocket, 2);
  close(clientSocket);

  struct timespec end_tvcl;
  clock_gettime(NULL, &end_tvcl);
  fprintf(stderr, "Client exiting after %d msgs (time: %d; clock_gettime: %f)\n",
          msg_count, time(NULL), end_tvcl.tv_sec + end_tvcl.tv_nsec / 1000000000.0);

  return 0;
}
