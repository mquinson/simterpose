#!/bin/bash

sudo LD_LIBRARY_PATH=/opt/simgrid/lib/ ./simterpose plat.xml deploy_small_ping_pong.xml --log=sd.:info --log=root.fmt:"'%l: [%c/%p]: %m%n'"
