#!/bin/bash

set -e # fail fast

make -C ../src/ simterpose
make -C apps/   pthread

rm -rf deploy_temp.xml
cat > deploy_temp.xml <<EOF
<?xml version='1.0'?>
<!DOCTYPE platform SYSTEM "http://simgrid.gforge.inria.fr/simgrid.dtd">
<platform version ="3">
  <process host="Tremblay" function="apps/pthread" start_time="0.00" />
</platform>
EOF

# To compile with a new version of SimGrid
sudo LD_LIBRARY_PATH=/opt/Simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml #--log=simterpose.:debug --log=msg.:debug  --log=simix_synchro.:debug # --log=simix.:debug   #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  #--log=xbt_dyn.:debug
# To compile with an old version of SimGrid
#sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ../src/simterpose -s platform.xml deploy_temp.xml #--log=simterpose.:debug --log=msg.:debug  --log=simix_synchro.:debug # --log=simix.:debug   #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  #--log=xbt_dyn.:debug

rm deploy_temp.xml
