#!/bin/bash

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ./simterpose -s plat.xml deploy_small_ping_pong_sendmsg.xml #--log=simterpose.:debug --log=msg.:debug  --log=simix_synchro.:debug # --log=simix.:debug   #--log=root.fmt:"'%l: [%c/%p]: %m%n'"  #--log=xbt_dyn.:debug
