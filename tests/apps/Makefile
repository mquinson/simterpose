BINS = send_server send_client \
       msg_client  msg_server  \
       pthread

# server_select client_select client_simple server_simple server_poll\
#	server_poll_multi server_close client_sbr server_sbr fcntl_ex server_read \
#	client_write  test_restore
CC = gcc

CFLAGS = -Wall -g
CFLAGS += -fno-common -Wunused -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wcomment
CFLAGS += -Wformat -Wwrite-strings -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-format-nonliteral

#CFLAGS += -Werror # This cannot be activated yet

all : $(BINS)

send_server : send_server.c
	$(CC) $(CFLAGS) -o send_server send_server.c
send_client : send_client.c
	$(CC) $(CFLAGS) -o send_client send_client.c
msg_server : msg_server.c
	$(CC) $(CFLAGS) -o msg_server msg_server.c
msg_client : msg_client.c
	$(CC) $(CFLAGS) -o msg_client msg_client.c

pthread: pthread.c
	$(CC) $(CFLAGS) -o pthread -pthread pthread.c

fcntl_ex: fcntl_ex.c
	$(CC) $(CFLAGS) -o fcntl_ex fcntl_ex.c

server_select: server_select.c
	$(CC) $(CFLAGS) -o server_select server_select.c

server_read : server_read.c
	$(CC) $(CFLAGS) -o server_read server_read.c

server_simple: serveur_simple.c
	$(CC) $(CFLAGS) -o server_simple serveur_simple.c

server_close: server_close.c
	$(CC) $(CFLAGS) -o server_close server_close.c

server_sbr: server_sbr.c
	$(CC) $(CFLAGS) -o server_sbr server_sbr.c

server_poll_multi: server_poll_multi.c
	$(CC) $(CFLAGS) -o server_poll_multi server_poll_multi.c

server_poll: server_poll.c
	$(CC) $(CFLAGS) -o server_poll server_poll.c

client_select: client_select.c
	$(CC) $(CFLAGS) -o client_select client_select.c

client_simple: client_simple.c
	$(CC) $(CFLAGS) -o client_simple client_simple.c

client_write : client_write.c
	$(CC) $(CFLAGS) -o client_write client_write.c

client_sbr : client_sbr.c
	$(CC) $(CFLAGS) -o client_sbr client_sbr.c

test_restore: test_restore.c
	$(CC) $(CFLAGS) -o test_restore test_restore.c

clean:
	rm -f $(BINS) *~
