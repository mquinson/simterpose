#!/bin/bash

set -e # fail fast

rm -f simterpose-send_clientserver.log
make -C ../src/ simterpose
make -C apps/   send_server send_client

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$1

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$sim_dir/lib/
export LD_LIBRARY_PATH
rm -f *.log
sudo $runner ../src/simterpose -s platform.xml send_clientserver.xml
#--log=simterpose.:debug #--log=simix_synchro.:debug  --log=msg.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'" #--log=simix.:debug
