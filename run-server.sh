#!/bin/sh
./tcp-proxy-fragmentation -i eth0  -m 84:78:ac:0d:97:c1 -l 2600:3c00::f03c:91ff:fe0f:4e7d -p 53 -d 8.8.8.8 &
