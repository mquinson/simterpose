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


#define SERV_PORT 2227

//#define BUFFER_SIZE 1024

int main(int argc, char **argv)
{

  if (argc < 3) {
    fprintf(stderr, "usage: %s amount_of_messages buffer_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int msg_count = atoi(argv[1]);
  int buffer_size = atoi(argv[2]);

  struct timespec tvcl;
  clock_gettime(NULL, &tvcl);
  fprintf(stderr, "Client starting: #msg: %d; (time: %d; clock_gettime: %f)\n",
          msg_count, time(NULL), tvcl.tv_sec + tvcl.tv_nsec / 1000000000.0);

  int clientSocket;
  u_short port;
  int res;
  char buff[buffer_size];
  strcpy(buff, "Message from client ");
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;


  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
    exit(1);
  }
  struct sockaddr_in cli_addr;
  memset(&cli_addr, 0, sizeof(struct sockaddr_in));
  host_addr = inet_addr("162.32.43.1");
  serverHostEnt = gethostbyname("162.32.43.1");
  memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
  port = SERV_PORT;
  cli_addr.sin_family = AF_INET;
  cli_addr.sin_port = htons(port);

  if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
    printf("echec demande de connexion\n");
    exit(1);
  }

  printf("Connexion avec le serveur établie %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
  struct iovec iov[1];
  struct msghdr msg;

  int msg_number = 0;

  for (msg_number = 0; msg_number < msg_count; ++msg_number) {

    memset(&msg, 0, sizeof(struct msghdr));
    sprintf(buff, "This is the message #%d produced on the client.", msg_number);

    iov[0].iov_base = buff;
    iov[0].iov_len = strlen(buff) + 1;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;


    res = sendmsg(clientSocket, &msg, 0);

    if (res == -1) {
      perror("erreur envoi client");
      exit(1);
    }
    fprintf(stderr, "Client: sent message #%d\n", msg_number);

  }
  shutdown(clientSocket, 2);
  close(clientSocket);

  struct timespec end_tvcl;
  clock_gettime(NULL, &end_tvcl);
  fprintf(stderr, "Client exiting after %d msgs (time: %d; clock_gettime: %f)\n",
          msg_count, time(NULL), end_tvcl.tv_sec + end_tvcl.tv_nsec / 1000000000.0);

  return 0;
}
