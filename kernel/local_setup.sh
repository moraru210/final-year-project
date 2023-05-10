#!/bin/bash

set -o errexit

pwd
cd /home/moraru210/Documents/eBPF/final-year-project/kernel

REUSE=false

# parse command line options
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -r|--reuse) REUSE=true; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# run xdp_loader with the appropriate options
if [ "$REUSE" = true ]; then
    ./xdp_loader -d lo -F --progsec xdp_tcp --auto-mode --reuse
else
    ./xdp_loader -d lo -F --progsec xdp_tcp --auto-mode
fi