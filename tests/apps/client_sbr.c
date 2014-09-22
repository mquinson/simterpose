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

#define BUFFER_SIZE 1024

int main()
{

  int clientSocket;
  u_short port;
  int res;
  char buff[BUFFER_SIZE];
  strcpy(buff, "Message from client");
  int server_socket;
  long host_addr;
  struct hostent *serverHostEnt;


  if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
    exit(1);
  } else {

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
      exit(0);
    } else {
      printf("Connexion avec le serveur établie\n");
      // while(1){
      //fgets(buff,512,stdin);
      res = send(clientSocket, buff, BUFFER_SIZE, 0);
      if (res == -1) {
        perror("erreur envoi client");
        exit(1);
      }
      printf("First message send\n");

      res = send(clientSocket, buff, BUFFER_SIZE, 0);
      if (res == -1) {
        perror("erreur envoi client");
        exit(1);
      }
      printf("Second message send\n");
    }
  }
  return 0;
}
