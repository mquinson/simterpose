all:
	make -C apps all

strace-client strace-server: apps/send_server apps/send_client
	strace apps/send_server 2227 5 128 >strace-server 2>&1&
	sleep 1
	strace apps/send_client 2227 5 128      >strace-client 2>&1&

clean:
	rm -f *~ strace-*
	make -C apps clean