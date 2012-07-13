OBJS = server client server_select client_select client_simple server_simple server_poll\
	server_poll_multi server_close client_sbr server_sbr fcntl_ex
CC = gcc 
CFLAGS = -Wall -g

all : $(OBJS)

server : server.c
	gcc -o server server.c

client : client.c
	gcc -o client client.c

fcntl_ex: fcntl_ex.c
	gcc -o fcntl_ex fcntl_ex.c

server_select: server_select.c
	gcc -o server_select server_select.c

server_simple: serveur_simple.c
	gcc -o server_simple serveur_simple.c

server_close: server_close.c
	gcc -o server_close server_close.c

server_sbr: server_sbr.c
	gcc -o server_sbr server_sbr.c

server_poll_multi: server_poll_multi.c
	gcc -o server_poll_multi server_poll_multi.c

server_poll: server_poll.c
	gcc -o server_poll server_poll.c

client_select: client_select.c
	gcc -o client_select client_select.c

client_simple: client_simple.c
	gcc -o client_simple client_simple.c

client_sbr : client_sbr.c
	gcc -o client_sbr client_sbr.c

clean:
	rm $(OBJS)