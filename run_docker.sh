#!/bin/bash

docker build . -q -t fastnsec3
docker run --network host -it -v.:/fastnsec3 fastnsec3 bash

