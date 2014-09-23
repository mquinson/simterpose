#!/bin/bash

set -e # fail fast

make -C ../src/ simterpose
make -C apps/   send_server send_client

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="apps/send_server" start_time="0.00">
    <argument value="2227"/> <!-- Port -->
    <argument value="5"/> <!-- Amount of messages to send -->
    <argument value="128"/>
  </process>
  <process host="Jupiter" function="apps/send_client" start_time="3.0">
    <argument value="162.32.43.1"/> <!-- IP -->
    <argument value="2227"/> <!-- Port -->
    <argument value="5"/>
    <argument value="128"/>
  </process>
</platform>
EOF

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml #--log=simterpose.:debug #--log=simix_synchro.:debug  --log=msg.:debug #--log=root.fmt:"'%l: [%c/%p]: %m%n'" #--log=simix.:debug

rm deploy_temp.xml