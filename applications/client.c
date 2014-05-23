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
  int msg_size = atoi(argv[2]);

  int clientSocket;
  u_short port;
  int res;
  char *buff = malloc(msg_size);
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;

  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Client: error while creating the real socket");
    exit(1);
  }
  struct timeval begin;
  struct timespec tvcl;
  struct sockaddr_in cli_addr;
  memset(&cli_addr, 0, sizeof(struct sockaddr_in));
  host_addr = inet_addr(IP);
  serverHostEnt = gethostbyname(IP);
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  port = SERV_PORT;
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);

  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    fprintf(stderr, "Client: Cannot connect to server: %s\n",strerror(errno));
    exit(1);
  }

  int msg_number = 0;

  /*   gettimeofday(&begin, NULL); 
     printf("\ngettimeofday du client: %f\n",begin.tv_sec + begin.tv_usec/1000000.0);
     printf("time du client: %d \n",time(NULL));
     clock_gettime(NULL, &tvcl); 
     printf("clock_gettime du client : %f\n\n",tvcl.tv_sec + tvcl.tv_nsec/1000000000.0); */

  for (msg_number = 0; msg_number < msg_count; ++msg_number) {
    res = send(clientSocket, buff, msg_size, 0);
    if (res == -1) {
      perror("Client: cannot send message");
      exit(1);
    } else {
      int length = msg_size;
      while (length > 0) {
        res = recv(clientSocket, buff, length, 0);
        if (res == -1) {
          fprintf(stderr, "Client: Error while sending message #%d: %s\n", msg_number, strerror(errno));
          exit(1);
        }
        length -= res;
      }
        fprintf(stderr, "Client: Received message #%d",msg_number);
    }
  }
  shutdown(clientSocket, 2);
  close(clientSocket);

  return 0;
}
