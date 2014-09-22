all:
	make -C src
	make -C tests all

clean:
	rm -rf simterpose *.o *~
	make -C src clean
	make -C tests clean
