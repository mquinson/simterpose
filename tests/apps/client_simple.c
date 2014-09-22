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
#include <arpa/inet.h>

#define SERV_PORT 2227

#define BUFFER_SIZE 1024

int main()
{

  int clientSocket;
  u_short port;
  int res;
  char buff[BUFFER_SIZE];
  strcpy(buff, "Message from client \n ");
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;


  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
    exit(1);
  } else {

    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(struct sockaddr_in));
    host_addr = inet_addr("162.32.43.1");       /*162.32.43.1 */
    serverHostEnt = gethostbyname("162.32.43.1");
    memcpy(&(cli_addr.sin_addr), serverHostEnt->h_addr, serverHostEnt->h_length);
    port = SERV_PORT;
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(port);

    if (connect(clientSocket, (struct sockaddr *) &cli_addr, sizeof(cli_addr)) < 0) {
      fprintf(stderr, "echec demande de connexion\n");
      exit(0);
    } else {
      fprintf(stderr, "Connexion avec le serveur établie %s:%d\n", inet_ntoa(cli_addr.sin_addr),
              ntohs(cli_addr.sin_port));
      int ia = 0;
      for (ia = 0; ia < 1000; ++ia) {
        res =
            sendto(clientSocket, buff, strlen(buff) + 1, 0, (struct sockaddr *) &cli_addr, sizeof(struct sockaddr_in));

        if (res == -1) {
          perror("erreur envoi client");
          exit(1);
        }
      }
    }
  }
  return 0;
}
