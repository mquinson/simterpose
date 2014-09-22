#!/bin/bash

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="apps/server_msg" start_time="0.00">
    <argument value="5"/> <!-- Amount of messages to send -->
    <argument value="128"/>
    <argument value="2227"/>
  </process>
  <process host="Jupiter" function="apps/client_msg" start_time="3.0">
    <argument value="5"/> <!-- Amount of messages to send -->
    <argument value="128"/>
  </process>
</platform>
EOF

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml #--log=simterpose.:debug --log=msg.:debug  --log=simix_synchro.:debug # --log=simix.:debug   #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  #--log=xbt_dyn.:debug
rm deploy_temp.xml