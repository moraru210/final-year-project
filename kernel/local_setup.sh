#!/bin/bash

set -o errexit

pwd
cd /home/moraru210/Desktop/final-year-project/kernel

../xdp-tools/xdp-loader/xdp-loader load -m skb lo xdp_prog_kern.o --pin-path /sys/fs/bpf/lo -v -s xdp_tcp