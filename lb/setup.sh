#!/bin/bash

set -o errexit

pwd
cd /home/moraru210/Documents/eBPF/final-year-project/lb
../testenv/testenv.sh setup -n test --legacy-ip
../testenv/testenv.sh exec -n test -- ./xdp_loader -d veth0 -F --progsec xdp_pass
../testenv/testenv.sh load -n test -- -F --progsec xdp_tcp