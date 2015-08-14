#!/bin/sh

# Run simterpose in valgrind but not its childs:
# make -C ../src/ simterpose && ./msg_clientserver.sh valgrind ; echo $?

set -e # fail fast

rm -f simterpose-sendto_clientserver.log
make -C ../src/ simterpose
make -C apps/   sendto_server sendto_client

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$1

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$sim_dir/lib/
export LD_LIBRARY_PATH

sudo LD_PRELOAD=../src/libsgtime.so $runner ../src/simterpose -s platform.xml sendto_clientserver.xml
#--log=simterpose.:debug
#--log=msg.:debug
# --log=simix_synchro.:debug
# --log=simix.:debug
#--log=root.fmt:"'%l: [%c/%p]: %m%n'"
#--log=xbt_dyn.:debug
