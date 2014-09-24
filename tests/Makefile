all:
	make -C apps all

strace-send_client.log strace-send_server.log: apps/send_server apps/send_client
	strace apps/send_server 2227 5 128 >strace-send_server.log 2>&1&
	sleep 1
	strace apps/send_client 127.0.0.1 2227 5 128 >strace-send_client.log 2>&1&

strace-msg_client.log strace-msg_server.log: apps/msg_server apps/msg_client
	strace apps/msg_server 2227 5 128 >strace-msg_server.log 2>&1&
	sleep 1
	strace apps/msg_client 127.0.0.1 2227 5 128 >strace-msg_client.log 2>&1&

simterpose-send_client.log: ../src/simterpose send_clientserver.sh apps/send_client.c apps/send_server.c
	./send_clientserver.sh

diff-send: strace-send_client.log simterpose-send_client.log
	diff -u simterpose-send_client.log strace-send_client.log
.PHONY: diff-send

	

clean:
	rm -f *~ strace-*.log simterpose-*.log
	make -C apps clean