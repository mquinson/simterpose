#!/bin/sh

# Run simterpose in valgrind but not its childs:
# make -C ../src/ simterpose && ./msg_clientserver.sh valgrind ; echo $?

set -e # fail fast

make -C ../src/ simterpose
make -C apps/   msg_server msg_client

# Allow to use another folder than /opt/Simgrid to execute
sim_dir=$1

# Allow to run under valgrind or gdb easily
VALGRIND_OPTS="--verbose --trace-children=no --child-silent-after-fork=yes"
export VALGRIND_OPTS

runner=$2

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$sim_dir/lib/
export LD_LIBRARY_PATH

sudo $runner ../simterpose -s platform.xml msg_clientserver.xml
#--log=simterpose.:debug
#--log=msg.:debug
# --log=simix_synchro.:debug
# --log=simix.:debug
#--log=root.fmt:"'%l: [%c/%p]: %m%n'"
#--log=xbt_dyn.:debug
