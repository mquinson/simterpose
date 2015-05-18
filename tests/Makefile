VERSION=new_version

all:
	make -C apps all

../src/simterpose: $(shell ls ../src/*.[ch])
	make -C ../src simterpose

# The "setarch x86_64 -R" part of the next command line is to get
# the kernel to not randomize the address space layout so that our
# traces are reproducible, so that we can effectively compare the
# output of simterpose and the one of strace. More info at:
# https://en.wikipedia.org/wiki/Address_space_layout_randomization

strace-send_client.log strace-send_server.log: apps/send_server apps/send_client
	setarch x86_64 -R strace apps/send_server 2227 5 128 >strace-send_server.log 2>&1&
	sleep 1
	setarch x86_64 -R strace apps/send_client 127.0.0.1 2227 5 128 >strace-send_client.log 2>&1&
simterpose-send_client.log: ../src/simterpose send_clientserver.sh apps/send_client.c apps/send_server.c
	./send_clientserver.sh $(VERSION)


diff-send: strace-send_client.log simterpose-send_client.log
	diff -u simterpose-send_client.log strace-send_client.log

strace-msg_client.log strace-msg_server.log: apps/msg_server apps/msg_client
	setarch x86_64 -R strace apps/msg_server 2227 5 128 >strace-msg_server.log 2>&1&
	sleep 1
	setarch x86_64 -R strace apps/msg_client 127.0.0.1 2227 5 128 >strace-msg_client.log 2>&1&
simterpose-msg_client.log: ../src/simterpose msg_clientserver.sh apps/msg_client.c apps/msg_server.c
	./msg_clientserver.sh  $(VERSION)
diff-msg: strace-msg_client.log simterpose-msg_client.log
	diff -u simterpose-msg_client.log strace-msg_client.log

strace-pthread.log: 
	setarch x86_64 -R strace apps/pthread > strace-pthread.log 2>&1
simterpose-pthread.log: ../src/simterpose pthread.sh
	./pthread.sh  $(VERSION)
diff-pthread: strace-pthread.log simterpose-pthread.log
	diff -u simterpose-pthread.log strace-pthread.log

.PHONY: diff-send diff-msg diff-pthread	

clean:
	rm -f *~ strace-*.log simterpose-*.log
	make -C apps clean
