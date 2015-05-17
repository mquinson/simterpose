#!/bin/bash

set -e # fail fast

make -C ../src/ simterpose
make -C apps/   msg_server msg_client

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="apps/msg_server" start_time="0.00">
    <argument value="2227"/> <!-- port -->
    <argument value="5"/> <!-- Amount of messages to send -->
    <argument value="128"/>
  </process>
  <process host="Jupiter" function="apps/msg_client" start_time="3.0">
    <argument value="162.32.43.1"/> <!-- IP -->
    <argument value="2227"/> <!-- port -->
    <argument value="5"/> <!-- Amount of messages to send -->
    <argument value="128"/>
  </process>
</platform>
EOF

# Allow to run under valgrind or gdb easily
runner=$1

# To compilse with a new version of SimGrid
sudo LD_LIBRARY_PATH=/opt/Simgrid/lib/ $runner ../src/simterpose -s platform.xml deploy_temp.xml --log=simterpose.:debug #--log=msg.:debug  --log=simix_synchro.:debug # --log=simix.:debug   #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  #--log=xbt_dyn.:debug
# To compile with an old version of SimGrid"
# sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ $runner ../src/simterpose -s platform.xml deploy_temp.xml --log=simterpose.:debug
#--log=msg.:debug  --log=simix_synchro.:debug # --log=simix.:debug   #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  #--log=xbt_dyn.:debug

rm deploy_temp.xml
