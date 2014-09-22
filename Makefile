src/simterpose: $(shell ls src/*.[ch])
	make -C src simterpose

applications/client: applications/client.c
	make -C applications client
applications/server: applications/server.c
	make -C applications server
applications/client_msg: applications/client_msg.c
	make -C applications client_msg
applications/server_msg: applications/server_msg.c
	make -C applications server_msg

clean:
	rm -rf simterpose *.o *~
	make -C src clean
	make -C applications clean	
