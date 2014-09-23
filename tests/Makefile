all:
	make -C apps all

strace-send-client strace-send-server: apps/send_server apps/send_client
	strace apps/send_server 2227 5 128 >strace-send-server 2>&1&
	sleep 1
	strace apps/send_client 127.0.0.1 2227 5 128 >strace-send-client 2>&1&

strace-msg-client strace-msg-server: apps/msg_server apps/msg_client
	strace apps/msg_server 2227 5 128 >strace-msg-server 2>&1&
	sleep 1
	strace apps/msg_client 127.0.0.1 2227 5 128 >strace-msg-client 2>&1&

clean:
	rm -f *~ strace-*
	make -C apps clean