#!/bin/bash

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ./simterpose_msg plat.xml deploy_small_ping_pong.xml --log=msg.:debug --log=root.fmt:"'%l: [%c/%p]: %m%n'" #--log=simix.:debug 