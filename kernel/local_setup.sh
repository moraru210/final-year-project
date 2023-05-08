#!/bin/bash

set -o errexit

pwd
cd /home/moraru210/Documents/eBPF/final-year-project/kernel
./xdp_loader -d lo -F --progsec xdp_tcp --auto-mode